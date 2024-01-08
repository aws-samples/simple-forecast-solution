# Amazon Forecast Accelerator

![](https://img.shields.io/badge/license-MIT--0-green)

**⚠️ NOTE: This repository is no longer maintained ⚠️**

Please use:
- [Amazon Forecast](https://aws.amazon.com/forecast/), for a low-code/no-code fully managed time series AI/ML forecasting service.
- [AutoGluon](https://github.com/autogluon/autogluon), if you prefer more control over the forecasting model exploration, training, and evaluation processes.

---

**Amazon Forecast Accelerator (AFA)** is an open-source application that:

- Enables users to run, test, and validate forecast accuracy in minutes rather than weeks,
- Performs model selection across 75+ statistical forecasting and machine learning techniques, and
- Exports forecasts and accuracy results as CSV files for benchmarking against existing forecast solutions.

![](images/afa-arch.png)

## :building_construction: Installation

### Manual Installation

_see [cdk/README.md](cdk/README.md)_

### One-Click Installation

1. Create/Login to AWS Account (a new AWS account is recommended for simplicity and testing purposes)
    - **Note**: For AWS Employees using internal AWS accounts - a new internal account is required.
2. Click on a "Launch Stack" button corresponding to your nearest AWS Region below:

Region name | Region code | Launch
--- | --- | ---
US East (Ohio) | us-east-2 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://us-east-2.console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
US West (Oregon) | us-west-2 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
Asia Pacific (Tokyo) | ap-northeast-1 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://ap-northeast-1.console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
Asia Pacific (Sydney) | ap-southeast-2 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://ap-southeast-2.console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
Asia Pacific (Singapore) | ap-southeast-1 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://ap-southeast-1.console.aws.amazon.com/cloudformation/home?region=ap-southeast-1#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
EU (Frankfurt) | eu-central-1 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://eu-central-1.console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)
EU (Ireland) | eu-west-1 | [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://eu-west-1.console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/quickcreate?templateUrl=https%3A%2F%2Fsfs-public.s3.ap-southeast-2.amazonaws.com%2Ftemplate.yaml&stackName=AfaBootstrapStack&param_instanceType=ml.t2.medium)

OR

Use the supplied CFN Template from 
_see [cfn/cfntemplate.yaml](cfn/cfntemplate.yaml)_ 

3. Enter your e-mail address in the "Parameters" section of the form, as shown below:

    > ![](images/cfn-email-parameter.png)

5. Acknowledge and Accept the cloudformation deployment, and click "Create stack" (which will begin deployment) as shown below:

    > ![](images/cfn-accept.png)

6. During the deployment, you will recieve an e-mail:
   - a subscription confirmation email with the subject heading "AWS Notification - Subscription Confirmation" from `AWS Notifications <no-reply@sns.amazonaws.com>`, by clicking "Confirm subscription" in the message body, you will recieve e-mails notifying when the AFA dashboard is deployed and when ML forecasting jobs are complete:
   > ![](images/sns-email-confirm.png) 
       
    **This must be accepted prior to the deployment completing, therefore we advise that you click "Confirm subscription" as soon as you receive the e-mail.**<br/><br/>
    Otherwise, if the deployment completes before confirming the subscription, you will not receive notifications and will need to monitor the deployment progress and access the application via the AWS Console, as follows:  

    1. Enter "Cloudformation" in the AWS Console search bar and select
    "CloudFormation" from the results list:

    > ![](images/aws-console-cfn.png)

    2. Deployment is complete when the four stacks below reach a
    "CREATE_COMPLETE" status:

    > ![](images/aws-console-cfn-stacks.png) 

    3. Once the deployment is complete, navigate to the Amazon SageMaker
    console via the AWS Console search bar:

    > ![](images/aws-console-sagemaker.png)

    4. Select "Open JupyterLab" in the list of Notebook instances:

    > ![](images/sagemaker-notebook-list.png)

    5. Open "Landing_Page.ipynb" in the file list on the left and if prompted
    with a "Select Kernel" window, click the
    "Select" button. This will bring you to the AFA landing page, which
    contains instructions on getting started with your forecasting.

    > ![](images/landing-page-example.png)
        
7. The deployment will complete in 15-20mins, click the URL in the notification
   e-mail, which will bring you to the AFA landing page (if you see a number of
   tiled icons, Open "Landing_Page.ipynb" in the file list on the left and if prompted
   with a "Select Kernel" window, click the "Select" button).
   
8. The Landing Page contains instructions on how to use the Amazon Forecast
   Accelerator application to generate forecasts and validate their performance.

## Important – AWS Resource Requirements

By default, Amazon Forecast Accelerator can process datasets of *up to 5,000 timeseries*
(1 timeseries = unique SKU x unique Channel) and uses [default AWS service limits for EC2 and Lambda](https://console.aws.amazon.com/servicequotas/).
*Refer to the table below for resource requirements based on # time-series in your dataset. A limit increase
will be required for larger data sets.*

| # Timeseries | SageMaker Notebbok Instance Type | # Concurrent Lambdas| [Est. Run-time](#run-time-and-pricing) | [Est. Cost per Forecast ($USD) w/ AWS Free-Tier](#run-time-and-pricing) | [Est. Cost per Forecast ($USD) w/o AWS Free-Tier](#run-time-and-pricing) |
|---|---|---|---|---|---|
| 1–5,000       | ml.t2.medium (default) | 1,000 (default)        | 1–5 mins (default)  | <$0.10       | <$0.30      |
|               |                        | 10,000[<sup>*</sup>](#upgrades-and-limit-increases)                 | 10s–1 min           | <$0.10       | <$0.30      |
| 5,000–10,000  | ml.t3.xlarge[<sup>*</sup>](#upgrades-and-limit-increases)             | 1,000 (default)        | 5–15min (default)   | <$0.10       | $0.30–$1.70 |
|               |                        | 10,000[<sup>*</sup>](#upgrades-and-limit-increases)                   | 30s–1.5 min         | <$0.10       | $0.30–$1.70 |
| 10,000–50,000 | ml.t3.2xlarge[<sup>*</sup>](#upgrades-and-limit-increases)            | 1,000 (default)        | 15–45min (default)  | <$0.10–$2.00 | $1.70–$9.00 |
|               |                        | 10,000[<sup>*</sup>](#upgrades-and-limit-increases)                   | 30s–1.5 min         | <$0.10–$2.00 | $1.70–$9.00 |
| 50,000–100,000 | ml.m4.4xlarge[<sup>*</sup>](#upgrades-and-limit-increases)           | 1,000 (default)        | 45+ min (default)  | $2.00–$10.00+ | $9.00–$16.80+ |
|                |                       | 10,000[<sup>*</sup>](#upgrades-and-limit-increases)                   | 5+ min             | $2.00–$10.00+ | $9.00–$16.80+ |

### <sup>*</sup>Upgrades and Limit Increases

A limit increase request is required to process larger datasets, which can be made in one of two ways:
- Self-Service (~24-48hr):
  - Request a SageMaker Notebook Instance type limit increase [here](https://aws.amazon.com/premiumsupport/knowledge-center/resourcelimitexceeded-sagemaker/).
  - Request an AWS Lambda concurrency limit increase via the instructions [here](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)
- Contact your AWS Account Manager (instant approval for SageMaker Notebook Instance type limit increass only)

### Run-time and Pricing

These estimates are for the **statistical forecasting models only** and were based on datasets with
three years of historical (weekly) demand for each time-series. The machine learning model run-time and costs
are defined by the Amazon Forecast service and take longer to train (typically hours). Please refer to the
[Amazon Forecast pricing](https://aws.amazon.com/forecast/pricing/) example for expected costs.

The frequency of the data (e.g. daily, weekly, monthly) significantly impacts the run-time. Datasets
containing monthly demand will yield the fastest run-times and can typically run using smaller SageMaker Notebook Instance types
when compared to weekly or daily demand data with the same number of time-series.
