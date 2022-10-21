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

    create_predictor_resp = afc.create_auto_predictor(
        PredictorName=AFC_PREDICTOR_NAME,
        ForecastHorizon=AFC_FORECAST_HORIZON,
        ForecastFrequency=AFC_FORECAST_FREQUENCY,
        DataConfig={
            "DatasetGroupArn": AFC_DATASET_GROUP_ARN,
            "AttributeConfigs":[
                {
                    "AttributeName": "demand",
                    "Transformations": {
                        "aggregation": "sum",
                        "frontfill": "none",
                        "middlefill": "zero",
                        "backfill": "zero"
                    }
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