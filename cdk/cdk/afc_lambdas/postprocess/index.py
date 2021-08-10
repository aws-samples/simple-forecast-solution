import os
import datetime
import json
import boto3
import pandas as pd
import awswrangler as wr

from urllib.parse import urlparse

SESSION = boto3.Session()
AFC = SESSION.client("forecast")
s3 = boto3.resource("s3")


def update_status_json(resp, state, path):
    """
    """

    parsed_url = urlparse(path, allow_fragments=False)
    bucket = parsed_url.netloc
    key = parsed_url.path.lstrip("/").rstrip("/")

    status_dict = dict(resp)
    status_dict["PROGRESS"] = {
        "state": state,
        "timestamp": datetime.datetime.now().astimezone().isoformat()
    }

    s3obj = s3.Object(bucket, key)
    s3obj.put(Body=bytes(json.dumps(status_dict).encode("utf-8")))

    return


def handler(event, context):
    """Reshape the Amazon Forecast csv files to AFA format.

    """

    payload = event["input"]["Payload"]
    prefix = payload["prefix"]
    forecast_export_job_arn = payload["ForecastExportJobArn"]
    s3_export_path = payload["s3_export_path"]

    update_status_json(payload, "IN_PROGRESS:post_processing",
        f'{s3_export_path}/{prefix}_status.json')

    resp = AFC.describe_forecast_export_job(
        ForecastExportJobArn=forecast_export_job_arn)

    # s3://<BUCKET>/afc-exports/<PREFIX>
    export_path = resp["Destination"]["S3Config"]["Path"]

    df = wr.s3.read_csv(os.path.join(export_path, f'{prefix}_ExportJob_*.csv'))
    df["date"] = pd.DatetimeIndex(df["date"]).strftime("%Y-%m-%d")
    df.rename({"date": "timestamp"}, axis=1, inplace=True)
    df[["channel", "family", "item_id"]] = df["item_id"].str.split("@@", expand=True)
    df.rename({"p50": "demand"}, axis=1, inplace=True)
    df.sort_values(by=["channel", "family", "item_id", "timestamp"],
        ascending=True, inplace=True)

    processed_csv_s3_path = os.path.join(export_path, f'{prefix}_processed.csv')
    wr.s3.to_csv(df, processed_csv_s3_path, index=False)

    # make AWS S3 console url
    parsed_url = urlparse(processed_csv_s3_path, allow_fragments=False)
    bucket = parsed_url.netloc
    key = parsed_url.path.lstrip("/").rstrip("/")

    console_url = "/".join([f"https://s3.console.aws.amazon.com/s3/object",
                            f"{bucket}?prefix={key}"])

    resp_out = payload
    resp_out["ProcessedCsvS3Path"] = processed_csv_s3_path
    resp_out["AwsS3ConsoleUrl"] = console_url

    update_status_json(resp_out, "DONE:post_processing",
        f'{s3_export_path}/{prefix}_status.json')

    return resp_out
