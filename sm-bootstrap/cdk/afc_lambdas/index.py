import os
import datetime
import json
import boto3

from urllib.parse import urlparse

session = boto3.Session()
afc = session.client("forecast")
afcq = session.client("forecastquery")
s3 = boto3.resource("s3")


def update_status_json(resp, state, path):
    """
    """

    parsed_url = urlparse(path, allow_fragments=False)
    bucket = parsed_url.netloc
    key = os.path.join(parsed_url.path.lstrip("/").rstrip("/"))

    status_dict = dict(resp)
    status_dict["PROGRESS"] = {
        "state": state,
        "timestamp": datetime.datetime.now().astimezone().isoformat()
    }

    s3obj = s3.Object(bucket, key)
    s3obj.put(Body=bytes(json.dumps(status_dict).encode("utf-8")))

    return


def prepare_handler(event, context):
    """
    """

    prefix = event["input"]["prefix"]
    data_frq = event["input"]["data_freq"]
    horiz = int(event["input"]["horiz"])
    freq = event["input"]["freq"]
    s3_path = event["input"]["s3_path"]
    s3_export_path = event["input"]["s3_export_path"]

    update_status_json(event["input"], "IN_PROGRESS:create_dataset_import",
        f'{s3_export_path}/{prefix}_status.json')

    assert(freq in ("D", "W", "M"))

    now_str = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    AFC_DATASET_DOMAIN = "RETAIL"
    AFC_DATASET_GROUP_NAME = f"{prefix}_DatasetGroup"
    AFC_DATASET_NAME = f"{prefix}_Dataset"
    AFC_DATASET_FREQUENCY = freq # "Y|M|W|D|H" (input frequency)
    AFC_DATASET_TYPE = "TARGET_TIME_SERIES"
    AFC_ROLE_ARN = os.environ["AFC_ROLE_ARN"]
    AFC_INPUT_S3_PATH = s3_path

    create_dataset_group_resp = afc.create_dataset_group(
        Domain=AFC_DATASET_DOMAIN,
        DatasetGroupName=AFC_DATASET_GROUP_NAME,
        DatasetArns=[])

    AFC_DATASET_GROUP_ARN = create_dataset_group_resp["DatasetGroupArn"]

    ts_schema = {
        "Attributes": [
            {"AttributeName": "timestamp",
             "AttributeType": "timestamp"},
            {"AttributeName": "demand",
             "AttributeType": "float"},
            {"AttributeName": "item_id",
             "AttributeType": "string"}
        ]
    }

    create_dataset_resp = afc.create_dataset(
        Domain=AFC_DATASET_DOMAIN,
        DatasetType=AFC_DATASET_TYPE,
        DatasetName=AFC_DATASET_NAME,
        DataFrequency=AFC_DATASET_FREQUENCY,
        Schema=ts_schema
    )

    AFC_DATASET_ARN = create_dataset_resp["DatasetArn"]

    afc.update_dataset_group(
        DatasetGroupArn=AFC_DATASET_GROUP_ARN,
        DatasetArns=[AFC_DATASET_ARN]
    )

    dataset_import_resp = afc.create_dataset_import_job(
        DatasetImportJobName=AFC_DATASET_GROUP_NAME,
        DatasetArn=AFC_DATASET_ARN,
        DataSource={
            "S3Config": {
                "Path": AFC_INPUT_S3_PATH,
                "RoleArn": AFC_ROLE_ARN
            }
        },
        TimestampFormat="yyyy-MM-dd"
    )

    AFC_DATASET_IMPORT_JOB_ARN = dataset_import_resp["DatasetImportJobArn"]

    status_json_s3_path = f'{s3_export_path}/{prefix}_status.json'

    resp_out = event["input"]
    resp_out["DatasetGroupArn"] = AFC_DATASET_GROUP_ARN
    resp_out["DatasetArn"] = AFC_DATASET_ARN
    resp_out["DatasetImportJobArn"] = dataset_import_resp["DatasetImportJobArn"]
    resp_out["StatusJsonS3Path"] = status_json_s3_path

    update_status_json(resp_out, "DONE:create_dataset_import",
        status_json_s3_path)
        
    return resp_out


def create_predictor_handler(event, context):
    """
    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]

    update_status_json(payload, "IN_PROGRESS:create_predictor",
        payload["StatusJsonS3Path"])

    AFC_DATASET_GROUP_ARN = payload["DatasetGroupArn"]
    AFC_FORECAST_HORIZON = payload["horiz"]
    AFC_FORECAST_FREQUENCY = payload["freq"]
    #AFC_ALGORITHM_NAME = "NPTS"
    #AFC_ALGORITHM_ARN = "arn:aws:forecast:::algorithm/NPTS"
    AFC_PREDICTOR_NAME = f"{prefix}_AutoML"

    create_predictor_resp = afc.create_predictor(
        PredictorName=AFC_PREDICTOR_NAME,
        ForecastHorizon=AFC_FORECAST_HORIZON,
        #AlgorithmArn=AFC_ALGORITHM_ARN, # TODO: delete this when ready
        PerformAutoML=True, # TODO: Uncomment this when ready
        #PerformHPO=False,
        InputDataConfig={
            "DatasetGroupArn": AFC_DATASET_GROUP_ARN
        },
        FeaturizationConfig={
            "ForecastFrequency": AFC_FORECAST_FREQUENCY,
            "Featurizations": [
                {
                    "AttributeName": "demand",
                    "FeaturizationPipeline": [
                        {
                            "FeaturizationMethodName": "filling",
                            "FeaturizationMethodParameters": {
                                "aggregation": "sum",
                                "frontfill": "none",
                                "middlefill": "zero",
                                "backfill": "zero"
                            }
                        }
                    ]
                }
            ]
        }
    )

    resp = payload
    resp["PredictorArn"] = create_predictor_resp["PredictorArn"]
    resp["PredictorName"] = AFC_PREDICTOR_NAME

    update_status_json(resp, "DONE:create_predictor",
        payload["StatusJsonS3Path"])

    return resp


def create_forecast_handler(event, context):
    """
    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]

    AFC_FORECAST_NAME = payload["PredictorName"]

    update_status_json(payload, "IN_PROGRESS:create_forecast",
        payload["StatusJsonS3Path"])

    create_forecast_resp = afc.create_forecast(
        ForecastName=AFC_FORECAST_NAME,
        PredictorArn=payload["PredictorArn"]
    )

    resp = payload
    resp["ForecastArn"] = create_forecast_resp["ForecastArn"]
    resp["ForecastName"] = AFC_FORECAST_NAME

    update_status_json(resp, "DONE:create_forecast",
        payload["StatusJsonS3Path"])

    return resp


def create_forecast_export_handler(event, context):
    """
    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]

    update_status_json(payload, "IN_PROGRESS:create_forecast_export",
        payload["StatusJsonS3Path"])

    AFC_FORECAST_EXPORT_JOB_NAME = f"{prefix}_ExportJob"

    resp = afc.create_forecast_export_job(
        ForecastExportJobName=AFC_FORECAST_EXPORT_JOB_NAME,
        ForecastArn=payload["ForecastArn"],
        Destination={
            "S3Config": {
                "Path": os.path.join(payload["s3_export_path"], prefix),
                "RoleArn": os.environ["AFC_ROLE_ARN"],
            }
        }
    )

    resp_out = payload
    resp_out["ForecastExportJobArn"] = resp["ForecastExportJobArn"]

    update_status_json(resp_out, "DONE:create_forecast_export",
        payload["StatusJsonS3Path"])

    return resp_out


def create_predictor_backtest_export_handler(event, context):
    """
    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]

    update_status_json(payload, "IN_PROGRESS:create_predictor_backtest_export",
        payload["StatusJsonS3Path"])

    backtest_export_job_name = f"{prefix}_BacktestExportJob"

    resp = afc.create_predictor_backtest_export_job(
        PredictorBacktestExportJobName=backtest_export_job_name,
        PredictorArn=payload["PredictorArn"],
        Destination={
            "S3Config": {
                "Path": os.path.join(payload["s3_export_path"], prefix),
                "RoleArn": os.environ["AFC_ROLE_ARN"],
            }
        }
    )

    resp_out = payload
    resp_out["PredictorBacktestExportJobArn"] = resp["PredictorBacktestExportJobArn"]

    update_status_json(resp_out, "IN_PROGRESS:create_predictor_backtest_export",
        payload["StatusJsonS3Path"])

    return resp_out


def delete_afc_resources_handler(event, context):
    """
    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]

    update_status_json(payload, "IN_PROGRESS:delete_afc_resources",
        payload["StatusJsonS3Path"])

    try:
        # Delete forecast export job
        afc.delete_forecast_export_job(
            ForecastExportJobArn=payload["ForecastExportJobArn"])
    except:
        pass

    try:
        # Delete forecast
        afc.delete_forecast(ForecastArn=payload["ForecastArn"])
    except:
        pass

    try:
        # Delete predictor
        afc.delete_predictor(PredictorArn=payload["PredictorArn"])
    except:
        pass

    try:
        # Delete dataset
        afc.delete_dataset(DatasetArn=payload["DatasetArn"])
    except:
        pass

    try:
        # Delete dataset import job
        afc.delete_dataset_import_job(
            DatasetImportJobArn=payload["DatasetImportJobArn"])
    except:
        pass

    try:
        # Delete dataset group
        afc.delete_dataset_group(DatasetGroupArn=payload["DatasetGroupArn"])
    except:
        pass

    update_status_json(payload, "DONE:delete_afc_resources",
        payload["StatusJsonS3Path"])

    return payload
