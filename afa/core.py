import traceback
import contextlib
import statsmodels.api as sm
import pandas as pd
import numpy as np
import time

from collections import OrderedDict
from concurrent import futures
from functools import partial
from tqdm.auto import tqdm

from scipy import signal, stats
from numpy import fft
from numpy.lib.stride_tricks import sliding_window_view

EXP_COLS = ["timestamp", "channel", "family", "item_id", "demand"]
GROUP_COLS = ["channel", "family", "item_id"]
OBJ_METRICS = ["smape_mean", "wape_mean"]

# these define how long a tail period is for each freq.
TAIL_LEN = {"D": 56, "W": 12, "W-MON": 12, "M": 3, "MS": 3}
DC_PERIODS = {"D": 365, "W": 7, "W-MON": 7, "M": 12, "MS": 12}

#
# Forecast functions
#
def forecaster(func):
    """Forecast function decorator. Apply this to any forecasting function and
    it will handle any compulsory pre- and post-processing of arguments and
    return values.

    """

    def do_forecast(y, horiz, freq, **kwargs):
        assert horiz > 0
        
        local_model = kwargs.get("local_model", False)
        seasonal = kwargs.get("seasonal", False)
        trim_zeros = kwargs.get("trim_zeros", False)
        use_log = kwargs.get("use_log", False)
        dc = kwargs.get("dc", None)

        if trim_zeros:
            y = np.trim_zeros(y, trim="f")

        if use_log:
            y = np.log1p(y)
            
        if local_model:
            y = y[-TAIL_LEN[freq]:]
            
        if len(y) == 1:
            y = np.pad(y, [1,0], constant_values=1)

        y = np.nan_to_num(y)

        # forecast via seasonal decomposition
        if seasonal:
            if dc is None:
                yp = np.zeros(horiz)
            else:
                period = DC_PERIODS[freq]

                if len(y) < 2 * period:
                    period = int(len(y) / 2)

                kwargs.pop("seasonal")

                resid, trend, yp_seasonal = dc
                #dc = sm.tsa.seasonal.seasonal_decompose(y, period=period, two_sided=False)
                #yp_seasonal = fourier(seas, horiz, freq, seasonal=False)
                yp_trend = func(np.nan_to_num(trend), horiz, **kwargs)
                yp_resid = func(np.nan_to_num(resid), horiz, **kwargs)
                yp = yp_seasonal + yp_trend + yp_resid
        else:
            # ensure the input values are not null
            yp = func(y, horiz, **kwargs)

        # de-normalize from log-scale
        if use_log:
            yp = np.exp(yp)

        yp = np.nan_to_num(yp).clip(0).round(0)
        
        assert len(yp) == horiz

        return yp

    return do_forecast


@forecaster
def exsmooth(y, horiz, **kwargs):
    """
    """

    alpha = kwargs.get("alpha", 0.2)

    if len(y) > 8:
        y = np.trim_zeros(y, trim ='f')
    if len(y) == 0:
        y = np.zeros(1)
        
    extra_periods = horiz-1

    f = [y[0]]

    # Create all the m+1 forecast
    for t in range(1,len(y)-1):
        f.append((1-alpha)*f[-1]+alpha*y[t])

    # Forecast for all extra months
    for t in range(extra_periods):
        # Update the forecast as the last forecast
        f.append(f[-1])    

    yp = np.array(f[-horiz:]).clip(0)

#   if use_log:
#       yp = np.exp(yp)

    return yp


@forecaster
def holt(y, horiz, **kwargs):
    """
    """

    alpha = kwargs.get("alpha", 0.2)
    beta = kwargs.get("beta", 0.2)
    extra_periods = horiz-1
    
    # Initialization
    f = [np.nan] # First forecast is set to null value
    a = [y[0]] # First level defined as the first demand point
    b = [y[1]-y[0]] # First trend is computed as the difference between the two first demand poiny

    # Create all the m+1 forecast
    for t in range(1,len(y)):
        # Update forecast based on last level (a) and trend (b)
        f.append(a[t-1]+b[t-1])

        # Update the level based on the new data point
        a.append(alpha*y[t]+(1-alpha)*(a[t-1]+b[t-1]))

        # Update the trend based on the new data point
        b.append(beta*(a[t]-a[t-1])+(1-beta)*b[t-1])

    # Forecast for all extra months
    for t in range(extra_periods):
        # Update the forecast as the most up-to-date level + trend
        f.append(a[-1]+b[-1])
        # the level equals the forecast
        a.append(f[-1])
        # Update the trend as the previous trend
        b.append(b[-1])

#   yp = np.clip(np.exp(f[-horiz:]), 0, None).round(0)
    yp = np.array(f[-horiz:])

    return yp


@forecaster
def fourier(y, horiz, n_harm=15, **kwargs):
    """Generate a forecast using Fourier extrapolation.

    Parameters
    ----------
    n_harm : int
        Number of harmonics in the model

    Results
    -------
    yp : array_like

    """
    
    try:
        n = y.shape[0]
        t = np.arange(n)
        p = np.polyfit(t, y, 1) # find linear trend in x
        f = fft.fftfreq(n) # frequencies

        y_detrended = y - p[0] * t # detrended x
        y_freqdom = fft.fft(y_detrended) # detrended x in frequency domain
        indices = list(range(n))

        # sort indices by frequency, lower -> higher
        indices.sort(key=lambda i: np.absolute(f[i]))
    
        t = np.arange(n + horiz)
        restored_sig = np.zeros(t.size)

        for i in indices[:2 + n_harm * 2]:
            amp = np.absolute(y_freqdom[i]) / n # amplitude
            phase = np.angle(y_freqdom[i]) # phase
            restored_sig += amp * np.cos(2 * np.pi * f[i] * t + phase)

        yp = (restored_sig + p[0] * t)[-horiz:]
    except:
        traceback.print_exc()
        yp = np.zeros(horiz)
        
    return yp


@forecaster
def naive(y, horiz, **kwargs):
    """
    """
    yp = np.clip(y.mean() * np.ones(horiz), 0, None).round(0)

    return yp


@forecaster
def trend(y, horiz, **kwargs):
    """Generate a forecast using a linear trend model.

    Parameters
    ----------
    y : array_like
    horiz : int

    Returns
    -------
    yp : np.array

    """

    def yp_linear(y, horiz):
        """Fit a simple linear model (AKA trend) and generate the
        corresponding forecast.

        """

        x = np.arange(y.size)
        mu = np.nanmean(y)
        y = y / mu
        theta = np.polyfit(x, y, 1)
        f = np.poly1d(theta)
        x1 = np.arange(len(y), len(y) + horiz)
        yp = f(x1) * mu

        return yp

    if y.sum() > 0:
        yp = yp_linear(y, horiz)
    else:
        yp = y.mean() * np.ones(horiz)

    return yp


@forecaster
def arima(y, horiz, q=1, d=0, p=1, **kwargs):
    """
    """

    try:
        extra_periods=horiz-1
        m = ARIMA(q, d, p)
        pred = m.fit_predict(y)
        pred = m.forecast(y, horiz)
        yp = np.round(pred[-horiz:],0)
    except:
        traceback.print_exc()
        yp = np.zeros(horiz)

    return yp


#
# ARIMA classes
#
class LinearModel:
    def __init__(self, fit_intercept=True):
        self.fit_intercept = fit_intercept
        self.beta = None
        self.intercept_ = None
        self.coef_ = None
    
    def _prepare_features(self, x):
        if self.fit_intercept:
            x = np.hstack((np.ones((x.shape[0], 1)), x))
        return x

    def _least_squares(self, x, y):
        return np.linalg.pinv((x.T @ x)) @ (x.T @ y)
    
    def fit(self, x, y):
        x = self._prepare_features(x)
        self.beta = self._least_squares(x, y)
        if self.fit_intercept:
            self.intercept_ = self.beta[0]
            self.coef_ = self.beta[1:]
        else:
            self.coef_ = self.beta
        
    def predict(self, x):
        x = self._prepare_features(x)
        return x @ self.beta
    
    def fit_predict(self, x, y):
        self.fit(x, y)
        return self.predict(x)


class ARIMA(LinearModel):
    def __init__(self, q, d, p):
        """
        An ARIMA model.
        :param q: (int) Order of the MA model.
        :param p: (int) Order of the AR model.
        :param d: (int) Number of times the data needs to be differenced.
        """
        super().__init__(True)
        self.p = p
        self.d = d
        self.q = q
        self.ar = None
        self.resid = None

    def _lag_view(self, x, order):
        """
        For every value X_i create a row that lags k values: [X_i-1, X_i-2, ... X_i-k]
        """
        y = x.copy()
        # Create features by shifting the window of `order` size by one step.
        # This results in a 2D array [[t1, t2, t3], [t2, t3, t4], ... [t_k-2, t_k-1, t_k]]
        x = np.array([y[-(i + order):][:order] for i in range(y.shape[0])])
        
        # Reverse the array as we started at the end and remove duplicates.
        # Note that we truncate the features [order -1:] and the labels [order]
        # This is the shifting of the features with one time step compared to the labels
        x = np.stack(x)[::-1][order - 1: -1]
        y = y[order:]

        return x, y

    def _difference(self, x, d=1):
        if d == 0:
            return x
        else:
            x = np.r_[x[0], np.diff(x)]
            return self._difference(x, d - 1)
        

    def _undo_difference(x, d=1):
        if d == 1:
            return np.cumsum(x)
        else:
            x = np.cumsum(x)
            return self._undo_difference(x, d - 1)
        
    def prepare_features(self, x):
        if self.d > 0:
            x = difference(x, self.d)
                    
        ar_features = None
        ma_features = None
        
        # Determine the features and the epsilon terms for the MA process
        if self.q > 0:
            if self.ar is None:
                self.ar = ARIMA(0, 0, self.p)
                self.ar.fit_predict(x)
            eps = self.ar.resid
            eps[0] = 0
            
            # prepend with zeros as there are no residuals_t-k in the first X_t
            ma_features, _ = self._lag_view(np.r_[np.zeros(self.q), eps], self.q)
            
        # Determine the features for the AR process
        if self.p > 0:
            # prepend with zeros as there are no X_t-k in the first X_t
            ar_features = self._lag_view(np.r_[np.zeros(self.p), x], self.p)[0]
                                
        if ar_features is not None and ma_features is not None:
            n = min(len(ar_features), len(ma_features)) 
            ar_features = ar_features[:n]
            ma_features = ma_features[:n]
            features = np.hstack((ar_features, ma_features))
        elif ma_features is not None: 
            n = len(ma_features)
            features = ma_features[:n]
        else:
            n = len(ar_features)
            features = ar_features[:n]
        
        return features, x[:n]
    
    def fit(self, x):
        features, x = self.prepare_features(x)
        super().fit(features, x)
        return features
            
    def fit_predict(self, x): 
        """
        Fit and transform input
        :param x: (array) with time series.
        """
        features = self.fit(x)
        return self.predict(x, prepared=(features))
    
    def predict(self, x, **kwargs):
        """
        :param x: (array)
        :kwargs:
            prepared: (tpl) containing the features, eps and x
        """
        features = kwargs.get('prepared', None)
        if features is None:
            features, x = self.prepare_features(x)
        
        y = super().predict(features)
        self.resid = x - y

        return self.return_output(y)
    
    def return_output(self, x):
        if self.d > 0:
            x = undo_difference(x, self.d) 
        return x
    
    def forecast(self, x, n):
        """
        Forecast the time series.
        
        :param x: (array) Current time steps.
        :param n: (int) Number of time steps in the future.
        """
        features, x = self.prepare_features(x)
        y = super().predict(features)
        
        # Append n time steps as zeros. Because the epsilon terms are unknown
        y = np.r_[y, np.zeros(n)]
        for i in range(n):
            feat = np.r_[y[-(self.p + n) + i: -n + i], np.zeros(self.q)]
            y[x.shape[0] + i] = super().predict(feat[None, :])
        return self.return_output(y)


#
# Analysis
#
def make_demand_classification(df, freq):
    """Run analyses on each timeseries, e.g. to determine
    retired/intermittent/continuous timeseries. This needs to be run on a
    non-normalized dataframe (i.e. prior to pre-processing in the pipeline).

    """

    def _retired(y):
        return y[-tail_len:].sum() < 1

    def _life_periods(y):
        y = np.trim_zeros(y)
        y = y[np.logical_not(np.isnan(y)) & (y > 0)]
        return len(y)

    def _category(r):
        if r["retired"]:
            if r["life_periods"] < r["len"] / 4.0:
                return "short"
            return "medium"
        else:
            return "continuous"

    def _spectral_entropy(y):
        y = y[np.logical_not(np.isnan(y))]
        f, Pxx_den = signal.periodogram(y)
        psd_norm = np.divide(Pxx_den, Pxx_den.sum())
        psd_norm += 1e-6
        return -np.multiply(psd_norm, np.log2(psd_norm)).sum().round(2)

    def _lambda_boxcox(y):
        return stats.boxcox(y.clip(lower=0.1))[1].round(2)

    assert "demand" in df

    tail_len = TAIL_LEN[freq]

#   df_analysis = \
#       ts_groups(df).agg({"demand": [_retired, _life_periods, len,
#                                     _spectral_entropy, _lambda_boxcox]})
    df_analysis = \
        ts_groups(df).agg({"demand": [_retired, _life_periods, len,
                                      _spectral_entropy]})

    # flatten column names
    df_analysis.columns = ["|".join([c.lstrip("_") for c in col])
                              .strip(" |")
                              .replace("demand|", "")
                           for col in df_analysis.columns.values]

    df_analysis["intermittent"] = df_analysis["spectral_entropy"] > 5.0

    # classify series as short, medium ("med"), or continuous ("cont")
    df_analysis["category"] = df_analysis.apply(_category, axis=1)

    df_analysis = df_analysis.astype({"life_periods": int, "len": int})

    return df_analysis


def make_perf_summary(df_results, metric="smape"):
    """Generate the dataframe summarizing the overall performance, primarily
    for use in the UI:

    - distribution of model types that were selected for each timeseries
    - errors for the best models
    - errors for the naive models

    Returns
    -------
    pd.DataFrame, pd.Series, pd.Series

    """
    df_best = df_results.query("rank == 1")

    # tabulate distribution of model types selected across the entire dataset
    df_model_dist = pd.DataFrame({"model_type": df_results["model_type"].unique()}) \
                      .merge(
                        df_best["model_type"] \
                                  .value_counts(normalize=True) \
                                  .reset_index() \
                                  .rename({"model_type": "perc",
                                           "index": "model_type"}, axis=1),
                        how="left", on="model_type") \
                      .merge(
                        df_best["model_type"] \
                                  .value_counts() \
                                  .reset_index() \
                                  .rename({"model_type": "freq",
                                           "index": "model_type"}, axis=1),
                        how="left", on="model_type")

    df_model_dist["perc"] = df_model_dist["perc"].fillna(0.) * 100.
    df_model_dist["freq"] = df_model_dist["freq"].fillna(0.)

    # get the metrics for the best naive models of each timeseries
    df_best_naive = \
        df_results.query("model_type == 'naive' and params == 'naive'") \
                  .sort_values(by=["rank"]) \
                  .groupby(GROUP_COLS, as_index=False, sort=False) \
                  .first()

    naive_err_mean = np.nanmean(np.hstack(df_best_naive[metric])).round(4)
    naive_err_median = np.nanmedian(np.hstack(df_best_naive[metric])).round(4)
    naive_err_std = np.nanstd(np.hstack(df_best_naive[metric])).round(4)

    naive_err = pd.Series({"err_mean": naive_err_mean,
                           "err_median": naive_err_median,
                           "err_std": naive_err_std })

    # summarize the metrics and improvement vs. naive
    err_mean = np.nanmean(np.hstack(df_best[metric])).round(4)
    err_median = np.nanmedian(np.hstack(df_best[metric])).round(4)
    err_std = np.nanstd(np.hstack(df_best[metric])).round(4)

    best_err = pd.Series({"err_mean": err_mean,
                          "err_median": err_median,
                          "err_std": err_std })

    return df_model_dist, best_err, naive_err


def make_health_summary(df, freq):
    """Analyze the timeseries of a dataframe, providing summaries of missing
    dates, min-max values, counts etc.

    Parameters
    ----------
    df : pd.DataFrame
    freq : str

    Returns
    -------
    pd.DataFrame

    """

    # no. of missing dates b/w the first and last dates of the timeseries
    def null_count(xs):
        return xs.isnull().sum().astype(int)

    def nonnull_count(xs):
        return (~xs.isnull()).sum().astype(int)

    # no. days of non-zero demand
    def nonzero_count(xs):
        return (xs > 0).sum().astype(int)

    def date_count(xs):
        return xs.index.nunique()

    df_summary = df.reset_index().rename({"index": "timestamp"}, axis=1)
    df_summary = \
        df_summary \
          .groupby(GROUP_COLS) \
          .agg({"demand": [null_count, nonzero_count, nonnull_count,
                           np.nanmean, np.nanmedian, len],
                "timestamp": [min, max]}) \
          .rename({"null_count": "missing_dates"}, axis=1)

    df_summary["pc_missing"] = (
        df_summary[("demand", "missing_dates")] / 
        ( df_summary[("demand", "missing_dates")] +
          df_summary[("demand", "nonnull_count")] )
    )
    df_summary.columns = df_summary.columns.map("_".join).str.strip("_")

    df_summary["pc_missing"] = np.round(df_summary["pc_missing"] * 100, 0)
    df_summary["demand_nanmean"] = np.round(df_summary["demand_nanmean"], 1)
    df_summary = df_summary.reset_index()

    return df_summary


def process_forecasts(wait_for, metric):
    """
    """

    # aggregate the forecasts
    raw_results = [f.result() for f in futures.as_completed(wait_for)]

    pred_lst = []
    results_lst = []

    for df_pred, df_results in raw_results:
        pred_lst.append(df_pred)
        results_lst.append(df_results)

    # results dataframe
    df_results = pd.concat(results_lst) \
                   .reset_index(drop=True)

    assert(df_results is not None)

    # predictions dataframe
    df_preds = pd.concat(pred_lst)
    df_preds.index.name = "timestamp"
    df_preds.reset_index(inplace=True)

    # generate performance summary
    df_model_dist, best_err, naive_err = make_perf_summary(df_results, metric)

    # keep only the best model results
    df_results = df_results[df_results["rank"] == 1]

    return df_results, df_preds, df_model_dist, best_err, naive_err


#
# Experiments
#
def create_model_grid():
    """Make the "grid" of model configurations to explore.

    Returns
    -------
    list

    """
    grid = [
        ("naive", partial(naive)),
        ("naive|local", partial(naive, local_model=True)),
        ("naive|seasonal", partial(naive, seasonal=True)),
        ("naive|local|seasonal",
            partial(naive, local_model=True, seasonal=True)),

        ("naive|log", partial(naive, use_log=True)),
        ("naive|log|local", partial(naive, use_log=True, local_model=True)),
        ("naive|log|seasonal", partial(naive, use_log=True, seasonal=True)),
        ("naive|log|local|seasonal",
            partial(naive, use_log=True, local_model=True, seasonal=True)),

        ("trend", partial(trend)),
        ("trend|local", partial(trend, local_model=True)),
        ("trend|seasonal", partial(trend, seasonal=True)),
        ("trend|local|seasonal",
            partial(trend, local_model=True, seasonal=True)),

        ("trend|log", partial(trend, use_log=True)),
        ("trend|log|local", partial(trend, use_log=True, local_model=True)),
        ("trend|log|seasonal", partial(trend, use_log=True, seasonal=True)),
        ("trend|log|local|seasonal",
            partial(trend, use_log=True, local_model=True, seasonal=True)),

        ("exsmooth|alpha=0.2", partial(exsmooth, alpha=0.2)),
        ("exsmooth|seasonal|alpha=0.2",
            partial(exsmooth, alpha=0.2, seasonal=True)),
        ("exsmooth|local|alpha=0.2",
            partial(exsmooth, alpha=0.2, local_model=True)),
        ("exsmooth|local|seasonal|alpha=0.2",
            partial(exsmooth, alpha=0.2, local_model=True, seasonal=True)),

        ("exsmooth|log|alpha=0.2", partial(exsmooth, alpha=0.2, use_log=True)),
        ("exsmooth|log|seasonal|alpha=0.2",
            partial(exsmooth, alpha=0.2, seasonal=True, use_log=True)),
        ("exsmooth|log|local|alpha=0.2",
            partial(exsmooth, alpha=0.2, local_model=True, use_log=True)),
        ("exsmooth|log|local|seasonal|alpha=0.2",
            partial(exsmooth, alpha=0.2, local_model=True, seasonal=True, use_log=True)),

        ("exsmooth|alpha=0.4", partial(exsmooth, alpha=0.4)),
        ("exsmooth|seasonal|alpha=0.4",
            partial(exsmooth, alpha=0.4, seasonal=True)),
        ("exsmooth|local|alpha=0.4",
            partial(exsmooth, alpha=0.4, local_model=True)),
        ("exsmooth|local|seasonal|alpha=0.4",
            partial(exsmooth, alpha=0.4, local_model=True, seasonal=True)),

        ("exsmooth|log|alpha=0.4", partial(exsmooth, alpha=0.4, use_log=True)),
        ("exsmooth|log|seasonal|alpha=0.4",
            partial(exsmooth, alpha=0.4, seasonal=True, use_log=True)),
        ("exsmooth|log|local|alpha=0.4",
            partial(exsmooth, alpha=0.4, local_model=True, use_log=True)),
        ("exsmooth|log|local|seasonal|alpha=0.4",
            partial(exsmooth, alpha=0.4, local_model=True, seasonal=True, use_log=True)),

        ("exsmooth|alpha=0.6", partial(exsmooth, alpha=0.6)),
        ("exsmooth|seasonal|alpha=0.6",
            partial(exsmooth, alpha=0.6, seasonal=True)),
        ("exsmooth|local|alpha=0.6",
            partial(exsmooth, alpha=0.6, local_model=True)),
        ("exsmooth|local|seasonal|alpha=0.6",
            partial(exsmooth, alpha=0.6, local_model=True, seasonal=True)),

        ("exsmooth|log|alpha=0.6", partial(exsmooth, alpha=0.6, use_log=True)),
        ("exsmooth|log|seasonal|alpha=0.6",
            partial(exsmooth, alpha=0.6, seasonal=True, use_log=True)),
        ("exsmooth|log|local|alpha=0.6",
            partial(exsmooth, alpha=0.6, local_model=True, use_log=True)),
        ("exsmooth|log|local|seasonal|alpha=0.6",
            partial(exsmooth, alpha=0.6, local_model=True, seasonal=True, use_log=True)),

        ("exsmooth|alpha=0.8", partial(exsmooth, alpha=0.8)),
        ("exsmooth|seasonal|alpha=0.8",
            partial(exsmooth, alpha=0.8, seasonal=True)),
        ("exsmooth|local|alpha=0.8",
            partial(exsmooth, alpha=0.8, local_model=True)),
        ("exsmooth|local|seasonal|alpha=0.8",
            partial(exsmooth, alpha=0.8, local_model=True, seasonal=True)),

        ("exsmooth|alpha=0.9", partial(exsmooth, alpha=0.9)),
        ("exsmooth|seasonal|alpha=0.9",
            partial(exsmooth, alpha=0.9, seasonal=True)),
        ("exsmooth|local|alpha=0.9",
            partial(exsmooth, alpha=0.9, local_model=True)),
        ("exsmooth|local|seasonal|alpha=0.9",
            partial(exsmooth, alpha=0.9, local_model=True, seasonal=True)),

        ("holt|alpha=0.2|beta=0.2", partial(holt, alpha=0.2, beta=0.2)),
        ("holt|seasonal|alpha=0.2|beta=0.2",
            partial(holt, alpha=0.2, beta=0.2, seasonal=True)),
        ("holt|local|alpha=0.2|beta=0.2",
            partial(holt, alpha=0.2, beta=0.2, local_model=True)),
        ("holt|local|seasonal|alpha=0.2|beta=0.2",
            partial(holt, alpha=0.2, beta=0.2, local_model=True, seasonal=True)),

        ("holt|alpha=0.4|beta=0.2", partial(holt, alpha=0.4, beta=0.2)),
        ("holt|seasonal|alpha=0.4|beta=0.2",
            partial(holt, alpha=0.4, beta=0.2, seasonal=True)),
        ("holt|local|alpha=0.4|beta=0.2",
            partial(holt, alpha=0.4, beta=0.2, local_model=True)),
        ("holt|local|seasonal|alpha=0.4|beta=0.2",
            partial(holt, alpha=0.4, beta=0.2, local_model=True, seasonal=True)),

        ("holt|alpha=0.6|beta=0.2", partial(holt, alpha=0.6, beta=0.2)),
        ("holt|seasonal|alpha=0.6|beta=0.2",
            partial(holt, alpha=0.6, beta=0.2, seasonal=True)),
        ("holt|local|alpha=0.6|beta=0.2",
            partial(holt, alpha=0.6, beta=0.2, local_model=True)),
        ("holt|local|seasonal|alpha=0.6|beta=0.2",
            partial(holt, alpha=0.6, beta=0.2, local_model=True, seasonal=True)),

        ("holt|alpha=0.2|beta=0.5",
            partial(holt, alpha=0.2, beta=0.5)),
        ("holt|seasonal|alpha=0.2|beta=0.5",
            partial(holt, alpha=0.2, beta=0.5, seasonal=True)),
        ("holt|local|alpha=0.2|beta=0.5",
            partial(holt, alpha=0.2, beta=0.5, local_model=True)),
        ("holt|local|seasonal|alpha=0.2|beta=0.5",
            partial(holt, alpha=0.2, beta=0.5, local_model=True, seasonal=True)),

        ("holt|alpha=0.4|beta=0.5", partial(holt, alpha=0.4, beta=0.5)),
        ("holt|seasonal|alpha=0.4|beta=0.5",
            partial(holt, alpha=0.4, beta=0.5, seasonal=True)),
        ("holt|local|alpha=0.4|beta=0.5",
            partial(holt, alpha=0.4, beta=0.5, local_model=True)),
        ("holt|local|seasonal|alpha=0.4|beta=0.5",
            partial(holt, alpha=0.4, beta=0.5, local_model=True, seasonal=True)),

        ("holt|alpha=0.6|beta=0.5", partial(holt, alpha=0.6, beta=0.5)),
        ("holt|seasonal|alpha=0.6|beta=0.5",
            partial(holt, alpha=0.6, beta=0.5, seasonal=True)),
        ("holt|local|alpha=0.6|beta=0.5",
            partial(holt, alpha=0.6, beta=0.5, local_model=True)),
        ("holt|local|seasonal|alpha=0.6|beta=0.5",
            partial(holt, alpha=0.6, beta=0.5, local_model=True, seasonal=True)),

        ("holt|alpha=0.8|beta=0.5", partial(holt, alpha=0.8, beta=0.5)),
        ("holt|seasonal|alpha=0.8|beta=0.5",
            partial(holt, alpha=0.8, beta=0.5, seasonal=True)),
        ("holt|local|alpha=0.8|beta=0.5",
            partial(holt, alpha=0.8, beta=0.5, local_model=True)),
        ("holt|local|seasonal|alpha=0.8|beta=0.5",
            partial(holt, alpha=0.8, beta=0.5, local_model=True, seasonal=True)),

        ("arima|001", partial(arima, q=0, d=0, p=1)),
        ("arima|001|local", partial(arima, q=0, d=0, p=1, local_model=True)),
        ("arima|001|seasonal", partial(arima, q=0, d=0, p=1, seasonal=True)),
        ("arima|001|seasonal|local", partial(arima, q=0, d=0, p=1,
            local_model=True, seasonal=True)),

        ("arima|101", partial(arima, q=1, d=0, p=1)),
        ("arima|101|local", partial(arima, q=1, d=0, p=1, local_model=True)),
        ("arima|101|seasonal", partial(arima, q=1, d=0, p=1, seasonal=True)),
        ("arima|101|seasonal|local", partial(arima, q=1, d=0, p=1,
            local_model=True, seasonal=True)),

        ("arima|201", partial(arima, q=2, d=0, p=1)),
        ("arima|201|local", partial(arima, q=2, d=0, p=1, local_model=True)),
        ("arima|201|seasonal", partial(arima, q=2, d=0, p=1, seasonal=True)),
        ("arima|201|seasonal|local", partial(arima, q=2, d=0, p=1,
            local_model=True, seasonal=True)),

        ("arima|log|201", partial(arima, q=2, d=0, p=1, use_log=True)),
        ("arima|log|201|local", partial(arima, q=2, d=0, p=1, local_model=True, use_log=True)),
        ("arima|log|201|seasonal", partial(arima, q=2, d=0, p=1, seasonal=True, use_log=True)),
        ("arima|log|201|seasonal|local", partial(arima, q=2, d=0, p=1,
            local_model=True, seasonal=True, use_log=True)),

        ("fourier", partial(fourier)),
        ("fourier|local", partial(fourier, local_model=True)),
        ("fourier|seasonal", partial(fourier, seasonal=True)),
        ("fourier|seasonal|local", partial(fourier, local_model=True, seasonal=True)),

        ("fourier|log", partial(fourier, use_log=True)),
        ("fourier|log|local", partial(fourier, local_model=True, use_log=True)),
        ("fourier|log|seasonal", partial(fourier, seasonal=True, use_log=True)),
        ("fourier|log|seasonal|local", partial(fourier, local_model=True, seasonal=True, use_log=True)),
    ]

    return grid


def run_cv(cfg, df, horiz, freq, cv_start, cv_stride=1, dc_dict=None,
    metric="smape"):
    """Run a sliding-window temporal cross-validation (aka backtest) using a 
    given forecasting function (`func`).
    
    """

    y = df["demand"].values

    # allow only 1D time-series arrays
    assert(y.ndim == 1)

    params, func = cfg
    
    if len(y) == 1:
        y = np.pad(y, [1, 0], constant_values=1)
        
    # the cross-val horizon length may shrink depending on the length of
    # historical data; shrink the horizon if it is >= the timeseries
    if horiz >= len(y):
        cv_horiz = len(y) - 1
    else:
        cv_horiz = horiz
        
    if len(df) == len(y):
        ts = df.index
    else:
        assert len(y) > len(df)
        diff = len(y) - len(df)
        ts = np.append(
            pd.date_range(end=df.index[0], freq=freq, periods=diff+1), df.index)

    # sliding window horizon actuals
    Y = sliding_window_view(y[cv_start:], cv_horiz)[::cv_stride,:]
    
    Ycv = []

    # |  y     |  horiz  |..............|
    # |  y      |  horiz  |.............|
    # |  y       |  horiz  |............|
    #   ::
    #   ::
    # |  y                    | horiz   |

    for i in range(cv_start, len(y)-cv_horiz+1, cv_stride):
        yp = func(y[:i], cv_horiz, freq, dc=dc_dict[i])
        Ycv.append(yp)

    # keep the backtest forecasts at each cv_stride
    Ycv = np.vstack(Ycv)
    
    # keep the backtest forecast time indices
    Yts = sliding_window_view(ts[cv_start:], cv_horiz)[::cv_stride,:]

    assert Yts.shape == Y.shape
    assert Yts.shape == Ycv.shape
    assert not np.any(np.isnan(Ycv))
    assert Ycv.shape == Y.shape

    # calc. error metrics
    df_results = calc_metrics(Y, Ycv, metric)
    df_results.insert(0, "model_type", params.split("|")[0])
    df_results.insert(1, "params", params)
    
    # store the final backtest window actuals and predictions
    df_results["y_cv"] = [Y]
    df_results["yp_cv"] = [Ycv]
    df_results["ts_cv"] =  [Yts]

    # generate the final forecast (1-dim)
    df_results["yhat"] = [func(y, horiz, freq, dc=dc_dict[len(y)-1])]
    
    return df_results


def run_cv_select(df, horiz, freq, metric="smape", cv_stride=3,
    cv_periods=None, show_progress=False):
    """Run the timeseries cross-val model selection across the forecasting
    functions for a single timeseries (`y`) and horizon length (`horiz`).

    """

    if horiz is None:
        horiz = int(df.iloc[0]["horiz"])
        
    channel = df.iloc[0]["channel"]
    family = df.iloc[0]["family"]
    item_id = df.iloc[0]["item_id"]

    assert len(df["demand"]) > 0

    # these are the model configurations to run
    grid = create_model_grid()
    #grid = [g for g in grid if "|log" not in g[0]]

    #
    # decompose sliding windows once
    #
    period = DC_PERIODS[freq]

    y = df["demand"].values

    if horiz >= len(y):
        cv_horiz = len(y) - 1
    else:
        cv_horiz = horiz

    if cv_periods is None:
        cv_start = 1
    else:
        cv_start = max(1, y.shape[0] - cv_periods) 

    dc_dict = {}

    y = df["demand"].values
    y = np.nan_to_num(y)

    if len(y) == 1:
        y = np.pad(y, [1,0], constant_values=1)

    for i in range(cv_start, len(y)):
        try:
            dc = sm.tsa.seasonal_decompose(y[:i], period=period, two_sided=False)
            yp_seasonal = fourier(dc.seasonal, horiz, freq, seasonal=False)
            vals = (dc.resid, dc.trend, yp_seasonal)
        except:
            vals = None

        dc_dict[i] = vals

    results = [run_cv(cfg, df, horiz, freq, cv_start, cv_stride,
                      dc_dict=dc_dict, metric=metric) for cfg in grid]

    df_results = pd.concat(results)

    # rank results by the metric
    df_results.sort_values(by=metric + "_mean", ascending=True, inplace=True)
    df_results["rank"] = np.arange(len(df_results)) + 1

    df_results.insert(0, "channel", channel)
    df_results.insert(1, "family", family)
    df_results.insert(2, "item_id", item_id)
    df_results.insert(3, "horiz", horiz)

    # get the forecast from the best model
    yhat = df_results.iloc[0]["yhat"]
    yhat_ts = pd.date_range(df.index.max(),
                            periods=len(yhat)+1, freq=freq, closed="right")
    
    # get the timeseries indices of the horizons
    df_horiz = df.iloc[-1].index

    assert len(yhat_ts) > 0
    assert len(yhat_ts) == len(yhat), f"{yhat_ts} {yhat}"

    # make the forecast dataframe
    df_pred = pd.DataFrame({"demand": yhat, "timestamp": yhat_ts})

    df_pred.insert(0, "channel", channel)
    df_pred.insert(1, "family", family)
    df_pred.insert(2, "item_id", item_id)
    df_pred.insert(3, "horiz", horiz)
    
    df_pred["type"] = "fcast"
    df_pred.set_index("timestamp", drop=False, inplace=True)

    df["type"] = "actual"

    # combine historical and predictions dataframes, re-ordering columns
    df_pred = df[GROUP_COLS + ["demand", "type"]] \
                .append(df_pred)[GROUP_COLS + ["demand", "type"]]

    return df_pred, df_results


def run_pipeline(data, freq_in, freq_out, metric="smape",
    cv_stride=1, backend="futures", tqdm_obj=None, horiz=None):
    """Run model selection over *all* timeseries in a dataframe. Note that
    this is a generator and will yield one results dataframe per timeseries at
    a single iteration.

    Parameters
    ----------
    data : str
    horiz : int
    freq_in : str
    freq_out : str
    obj_metric : str, optional
    cv_stride : int
        Stride length of cross-validation sliding window. For example, a
        `cv_stride=2` for `freq_out='W'` means the cross-validation will be
        performed every 2 weeks in the training data. Smaller values will lead
        to longer model selection durations.
    backend : str, optional
        "multiprocessing", "pyspark", or "lambdamap"

    """
    
    if horiz is None:
        df_horiz = data[GROUP_COLS + ["horiz"]].drop_duplicates()

    df = load_data(data, freq_in)

    # resample the input dataset to the desired frequency.
    df = resample(df, freq_out)
    
    if horiz is None:
        df["timestamp"] = df.index
        df = df.merge(df_horiz, on=GROUP_COLS, how="left")
        df.set_index("timestamp", inplace=True)
        group_cols = GROUP_COLS + ["horiz"]
    else:
        group_cols = GROUP_COLS
    
    groups = df.groupby(group_cols, as_index=False, sort=False)
    job_count = groups.ngroups

    if backend == "python": 
        results = \
            [run_cv_select(dd, horiz, freq_out, metric, cv_stride)
                 for _, dd in groups]
    elif backend == "futures":
        ex = futures.ProcessPoolExecutor()

        wait_for = [
            ex.submit(run_cv_select,
                *(dd, horiz, freq_out, metric, cv_stride))
                for _, dd in groups
        ]

        # return the list of futures
        results = wait_for
    elif backend == "pyspark":
        raise NotImplementedError
    elif backend == "lambdamap":
        raise NotImplementedError
    else:
        raise NotImplementedError

    return results


#
# Error metrics
#
def calc_metrics(Y, Ycv, metric="smape"):
    """Note, this operates on 2D arrays of sliding window values.

    """

    assert Y.ndim == Ycv.ndim == 2
    assert Y.shape == Ycv.shape

    # calc. error metrics
    df_metrics = pd.DataFrame()

    metric_aggs = [
        ("mean", np.nanmean),
        ("median", np.nanmedian),
        ("std", np.nanstd)
    ]

    if metric == "smape":
        metric_func = calc_smape
    elif metric == "wape":
        metric_func = calc_wape
    else:
        raise NotImplementedError

    df_metrics[metric] = [metric_func(Y, Ycv)]

    for agg, agg_func in metric_aggs:
        df_metrics[f"{metric}_{agg}"] = \
            df_metrics[metric].apply(agg_func).round(4)

    assert(len(df_metrics) == 1)

    return df_metrics
    

def calc_smape(y, yp, axis=0, smooth=True):
    """Calculate the symmetric mean absolute percentage error (sMAPE).
    
    sMAPE is calulated as follows:
    
        sMAPE = Σ|y - yp| / Σ(y + yp)
    
    where, 0.0 <= sMAPE <= 1.0 (lower is better)
    
    """
    try:
        eps = 1 / y.shape[0]

        if smooth:
            y2, yp2 = y + eps, yp + eps
        else:
            y2, yp2 = y, yp

        try:
            smape = np.divide(np.nansum(np.abs(y2 - yp2), axis=axis),
                              np.nansum(y2 + yp2, axis=axis))
        except ZeroDivisionError:
            smape = 0.0
    except ZeroDivisionError:
        return np.nan
        
    return np.round(smape, 4)


def calc_wape(y, yp):
    wape = np.nansum(np.abs(y-yp)) / (1 + np.nansum(np.abs(y)))
    return wape.round(4)


#
# Data wrangling
#
def load_data(data, impute_freq=None):
    """Read a raw timeseries dataset from disk, S3, or a dataframe. Note that
    the "timestamp" column will be removed as a bonafide column and set as 
    the dataframe (timeseries) index.

    Parameters
    ----------
    data : str or pd.DataFrame
        Path to the data file if `str`, otherwise a "raw" timeseries dataframe.
    impute_freq : str or None; optional
        If `str`, impute the missing dates between the first and last
        dates, according to the sampling frequency `str` value.

    Returns
    -------
    Dataset

    """

    if isinstance(data, str):
        if data.endswith(".csv.gz"):
            _read_func = partial(pd.read_csv, compression="gzip")
        elif data.endswith(".csv"):
            _read_func = partial(pd.read_csv)
        else:
            raise NotImplementedError

        # cast exp. columns to correct types
        df = _read_func(data)
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        raise NotImplementedError

    # enforce column datatypes
    df = df.astype({"channel": str, "family": str, "item_id": str,
                    "demand": float})

    # set timeseries dataframe index
    if "timestamp" in df:
        df.set_index(pd.DatetimeIndex(df.pop("timestamp")), inplace=True)

    df.index.name = None

    if impute_freq is not None:
        df = impute_dates(df, impute_freq)

    df["demand"] = df["demand"].clip(0).round(0)

    return df


def impute_dates(df, freq, dt_stop=None):
    """Fill missing dates in the timeseries dataframe.

    Parameters
    ----------
    dd : pd.DataFrame
    freq : str
    dt_stop : str or datetime, optional
        The final date in the timeseries, it will be inferred if not specified.
        Otherwise, dates will be imputed between the end of the the timeseries
        and this date.

    Returns
    -------
    pd.DataFrame

    """

    def _impute_dates(dd, freq, dt_stop=None):
        """
        """

        if dt_stop is None:
            dt_stop = dd.index.max()

        dt_stop = pd.Timestamp(dt_stop)

        # don't shrink timeseries
        assert dt_stop >= dd.index.max(), \
            "`dt_stop` must be >= the last date in this timeseries"

        # assign the new timeseries index
        dd = dd.reindex(pd.date_range(dd.index.min(), dt_stop, freq=freq))

        # fwd fill only the essential columns
        dd.loc[:,GROUP_COLS] = dd[GROUP_COLS].ffill()

        return dd

    assert isinstance(df.index, pd.DatetimeIndex)

    if "timestamp" in df:
        df.drop("timestamp", axis=1, inplace=True)

    df = ts_groups(df).apply(partial(_impute_dates, freq=freq, dt_stop=dt_stop))
    df.index = df.index.droplevel(0)

    return df


def resample(df, freq):
    """Resample a dataframe to a new frequency. Note that if a period in the
    new frequency contains only nulls, then the resulting resampled sum is NaN.

    Parameters
    ----------
    df : pd.DataFrame
    freq : str

    """

    df = df.groupby(GROUP_COLS, sort=False) \
           .resample(freq) \
           .agg({"demand": _sum}) \
           .reset_index(level=[0,1,2])

    return df


#
# Utilities
#
def validate(df):
    """Validate the timeseries dataframe

    """

    err_msgs = []
    warn_msgs = []

    # check column names
    for col in EXP_COLS:
        if col not in df:
            err_msgs.append(f"**{col}** column missing")

    msgs = {
        "errors": err_msgs,
        "warnings": warn_msgs
    }

    is_valid_file = len(err_msgs) == 0

    return msgs, is_valid_file


def ts_groups(self, **groupby_kwds):
    """Helper function to get the groups for a timeseries dataframe.

    """
    groupby_kwds.setdefault("as_index", False)
    groupby_kwds.setdefault("sort", False)

    return self.groupby(GROUP_COLS, **groupby_kwds)


def _sum(y):
    if np.all(pd.isnull(y)):
        return np.nan
    return np.nansum(y)
