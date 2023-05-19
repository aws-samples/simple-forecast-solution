import os
from textwrap import dedent

import aws_cdk as core
from aws_cdk import Aws, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sagemaker as sm
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct

PWD = os.path.dirname(os.path.realpath(__file__))

TAG_NAME = "Project"
TAG_VALUE = "Afa"
RACC = f"{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}"


class AfaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(
            scope,
            construct_id,
            **{"description": "Amazon Forecast Accelerator (uksb-1s7c5ojr9)"},
        )
        email_address = core.CfnParameter(
            self,
            "emailAddress",
            description="(Required) An e-mail address with which to receive "
            "deployment notifications.",
        )

        instance_type = core.CfnParameter(
            self,
            "instanceType",
            default="ml.t3.large",
            description="(Required) SageMaker Notebook instance type on which to host "
            "the AFA dashboard (e.g. ml.t2.medium, ml.t3.xlarge, ml.t3.2xlarge, "
            "ml.m4.4xlarge)",
        )

        self.afa_branch = core.CfnParameter(self, "afaBranch", default="main")
        self.lambdamap_branch = core.CfnParameter(
            self, "lambdamapBranch", default="main"
        )
        self.lambdamap_function_name = kwargs.get(
            "lambdamap_function_name", "AfaLambdaMapFunction"
        )
        self.kms_key = kms.Key(self, "AfaKmsKey", enable_key_rotation=True)
        self.lambdas = []

        #
        # S3 Bucket
        #
        logs_bucket = s3.Bucket(
            self,
            "LogBucket",
            auto_delete_objects=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
        )

        logs_bucket.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {"id": "W35", "reason": "This is the access logging bucket."},
                ]
            }
        }

        bucket = s3.Bucket(
            self,
            "Bucket",
            auto_delete_objects=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=logs_bucket,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
        )

        #
        # SSM Parameter Store
        #
        ssm.StringParameter(
            self,
            "AfaSsmS3Bucket",
            string_value=bucket.bucket_name,
            parameter_name="AfaS3Bucket",
        )

        ssm.StringParameter(
            self,
            "AfaSsmS3InputPath",
            string_value=f"s3://{bucket.bucket_name}/input/",
            parameter_name="AfaS3InputPath",
        )

        ssm.StringParameter(
            self,
            "AfaSsmS3OutputPath",
            string_value=f"s3://{bucket.bucket_name}/afc-exports/",
            parameter_name="AfaS3OutputPath",
        )

        #
        # SNS topic for email notification
        #
        topic = sns.Topic(
            self,
            "NotificationTopic",
            topic_name=f"{construct_id}-NotificationTopic",
            master_key=self.kms_key,
        )

        topic.add_subscription(
            subscriptions.EmailSubscription(email_address.value_as_string)
        )

        self.topic = topic

        sns_lambda_role = iam.Role(
            self,
            "SnsEmailLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSFullAccess")
            ],
        )

        iam.Policy(
            self,
            "SnsLambdaPolicy",
            roles=[sns_lambda_role],
            statements=[
                # Logging
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:PutLogEvents",
                    ],
                    resources=[
                        f"arn:aws:logs:{RACC}:log-group:/aws/lambda/"
                        f"{core.Aws.STACK_NAME}*"
                    ],
                ),
                # SNS
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["sns:Publish"],
                    resources=[f"arn:aws:sns:{RACC}:{core.Aws.STACK_NAME}*"],
                ),
            ],
        )

        self.sns_lambda_role = sns_lambda_role
        self.kms_key.grant_encrypt_decrypt(self.sns_lambda_role)

        sns_lambda = lambda_.Function(
            self,
            "SnsEmailLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            environment={"TOPIC_ARN": f"arn:aws:sns:{RACC}:{topic.topic_name}"},
            code=self.make_dashboard_ready_email_inline_code(),
            handler="index.lambda_handler",
            role=sns_lambda_role,
        )

        self.lambdas.append(sns_lambda)

        #
        # Notebook lifecycle configuration
        #
        notebook_instance_name = f"{construct_id}-NotebookInstance"
        lcc = self.make_nb_lcc(
            construct_id, notebook_instance_name, sns_lambda.function_name
        )
        #
        # Notebook role
        #
        sm_role = iam.Role(
            self,
            "NotebookRole",
            assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )

        self.kms_key.grant_encrypt_decrypt(sm_role)

        sm_policy = iam.Policy(
            self,
            "SmPolicy",
            roles=[sm_role],
            statements=[
                # Lambda
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:InvokeFunction",
                    ],
                    resources=[
                        f"arn:aws:lambda:{RACC}:function:"
                        f"{self.lambdamap_function_name}",
                        f"arn:aws:lambda:{RACC}:function:{core.Aws.STACK_NAME}*",
                    ],
                ),
                # S3
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject*",
                        "s3:PutObject*",
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetEncryptionConfiguration",
                    ],
                    resources=[
                        f"arn:aws:s3:::{construct_id.lower()}*",
                    ],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # SageMaker
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "sagemaker:DescribeNotebookInstanceLifecycleConfig",
                        "sagemaker:DeleteNotebookInstance",
                        "sagemaker:StopNotebookInstance",
                        "sagemaker:DescribeNotebookInstance",
                        "sagemaker:CreateNotebookInstanceLifecycleConfig",
                        "sagemaker:DeleteNotebookInstanceLifecycleConfig",
                        "sagemaker:UpdateNotebookInstanceLifecycleConfig",
                        "sagemaker:CreateNotebookInstance",
                        "sagemaker:UpdateNotebookInstance",
                    ],
                    resources=[
                        f"arn:aws:sagemaker:{RACC}:notebook-instance/"
                        f"{construct_id.lower()}*",
                        f"arn:aws:sagemaker:{RACC}:"
                        "notebook-instance-lifecycle-config/notebooklifecycleconfig*",
                    ],
                ),
                # Step Functions
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "states:DescribeExecution",
                        "states:DescribeActivity",
                        "states:DescribeStateMachine*",
                        "states:GetExecutionHistory",
                        "states:GetActivityTask",
                        "states:ListExecutions",
                        "states:StartExecution",
                        "states:StopExecution",
                        "states:ListTagsForResource",
                    ],
                    resources=[
                        f"arn:aws:states:{RACC}:*:{core.Aws.STACK_NAME}*",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "states:ListStateMachines",
                    ],
                    resources=[
                        f"arn:aws:states:{RACC}:*:{core.Aws.STACK_NAME}*",
                    ],
                ),
                # SSM
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["ssm:GetParameter*", "ssm:PutParameter"],
                    resources=[
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3Bucket",
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3InputPath",
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3OutputPath",
                        f"arn:aws:ssm:{RACC}:parameter/AfaAfcStateMachineArn",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ssm:DescribeParameters",
                    ],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
            ],
        )

        sm_policy.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {"id": "W12", "reason": "Certain actions require '*' resources."},
                ]
            }
        }

        #
        # Notebook instance
        #
        sm.CfnNotebookInstance(
            self,
            "NotebookInstance",
            role_arn=sm_role.role_arn,
            instance_type=instance_type.value_as_string,
            notebook_instance_name=notebook_instance_name,
            volume_size_in_gb=16,
            lifecycle_config_name=lcc.attr_notebook_instance_lifecycle_config_name,
            kms_key_id=self.kms_key.key_id,
        )

        # AFC/Lambda role
        afc_role = iam.Role(
            self,
            "AfcRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("forecast.amazonaws.com"),
                iam.ServicePrincipal("lambda.amazonaws.com"),
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonForecastFullAccess"
                ),
            ],
        )

        self.kms_key.grant_encrypt_decrypt(afc_role)

        iam.Policy(
            self,
            "AfcPolicy",
            roles=[afc_role],
            statements=[
                # Lambda
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:InvokeFunction",
                    ],
                    resources=[
                        f"arn:aws:lambda:{RACC}:function:"
                        f"{self.lambdamap_function_name}",
                        f"arn:aws:lambda:{RACC}:function:{core.Aws.STACK_NAME}*",
                    ],
                ),
                # S3
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject*",
                        "s3:PutObject*",
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetEncryptionConfiguration",
                        "s3:GetBucketPolicy",
                        "s3:GetBucketTagging",
                    ],
                    resources=[
                        f"arn:aws:s3:::{construct_id.lower()}*",
                    ],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # Logging
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:PutLogEvents",
                    ],
                    resources=[
                        f"arn:aws:logs:{RACC}:log-group:/aws/lambda/"
                        f"{core.Aws.STACK_NAME}*"
                    ],
                ),
                # SNS
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["sns:Publish"],
                    resources=[f"arn:aws:sns:{RACC}:{core.Aws.STACK_NAME}*"],
                ),
            ],
        )

        #
        # PREPARE DATA
        #
        prepare_lambda = lambda_.Function(
            self,
            "PrepareLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.prepare_handler",
            code=lambda_.Code.from_inline(
                open(os.path.join(PWD, "afc_lambdas", "prepare.py")).read()
            ),
            environment={"AFC_ROLE_ARN": afc_role.role_arn},
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(prepare_lambda)

        prepare_step = tasks.LambdaInvoke(
            self,
            "PrepareDataStep",
            lambda_function=prepare_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        #
        # CREATE PREDICTOR
        #
        create_predictor_lambda = lambda_.Function(
            self,
            "CreatedPredictorLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.create_predictor_handler",
            code=lambda_.Code.from_inline(
                open(os.path.join(PWD, "afc_lambdas", "create_predictor.py")).read()
            ),
            environment={"AFC_ROLE_ARN": afc_role.role_arn},
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(create_predictor_lambda)

        create_predictor_step = tasks.LambdaInvoke(
            self,
            "CreatePredictorStep",
            lambda_function=create_predictor_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        create_predictor_step.add_retry(
            backoff_rate=1.05,
            interval=core.Duration.seconds(60),
            max_attempts=1000,
            errors=[
                "ResourceNotFoundException",
                "ResourceInUseException",
                "ResourcePendingException",
            ],
        )

        #
        # CREATE FORECAST
        #
        create_forecast_lambda = lambda_.Function(
            self,
            "CreatedForecastLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.create_forecast_handler",
            code=lambda_.Code.from_inline(
                open(os.path.join(PWD, "afc_lambdas", "create_forecast.py")).read()
            ),
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(create_forecast_lambda)

        create_forecast_step = tasks.LambdaInvoke(
            self,
            "CreateforecastStep",
            lambda_function=create_forecast_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        create_forecast_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=[
                "ResourceNotFoundException",
                "ResourceInUseException",
                "ResourcePendingException",
            ],
        )

        #
        # CREATE FORECAST EXPORT
        #
        create_forecast_export_lambda = lambda_.Function(
            self,
            "CreateExportLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.create_forecast_export_handler",
            code=lambda_.Code.from_inline(
                open(os.path.join(PWD, "afc_lambdas", "create_export.py")).read()
            ),
            environment={"AFC_ROLE_ARN": afc_role.role_arn},
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(create_forecast_export_lambda)

        create_forecast_export_step = tasks.LambdaInvoke(
            self,
            "CreateExportStep",
            lambda_function=create_forecast_export_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        create_forecast_export_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceInUseException", "ResourcePendingException"],
        )

        #
        # BACKTEST EXPORT FILE(s)
        #
        create_predictor_backtest_export_lambda = lambda_.Function(
            self,
            "CreatePredictorBacktestExportLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.create_predictor_backtest_export_handler",
            code=lambda_.Code.from_inline(
                open(
                    os.path.join(
                        PWD, "afc_lambdas", "create_predictor_backtest_export.py"
                    )
                ).read()
            ),
            environment={"AFC_ROLE_ARN": afc_role.role_arn},
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(create_predictor_backtest_export_lambda)

        create_predictor_backtest_export_step = tasks.LambdaInvoke(
            self,
            "CreatePredictorBacktestExportStep",
            lambda_function=create_predictor_backtest_export_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        create_predictor_backtest_export_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceInUseException", "ResourcePendingException"],
        )

        #
        # POSTPROCESS FORECAST EXPORT FILE(s)
        #
        postprocess_lambda = lambda_.Function(
            self,
            "PostProcessLambda",
            code=lambda_.EcrImageCode.from_asset_image(
                directory=os.path.join(PWD, "afc_lambdas", "postprocess")
            ),
            runtime=lambda_.Runtime.FROM_IMAGE,
            handler=lambda_.Handler.FROM_IMAGE,
            memory_size=3000,
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(postprocess_lambda)

        postprocess_step = tasks.LambdaInvoke(
            self,
            "PostProcessStep",
            lambda_function=postprocess_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        postprocess_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(30),
            max_attempts=2000,
            errors=[
                "NoFilesFound",
                "ResourceInUseException",
                "ResourcePendingException",
            ],
        )

        # DELETE AFC RESOURCES
        delete_afc_resources_lambda = lambda_.Function(
            self,
            "DeleteAfcResourcesLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            handler="index.delete_afc_resources_handler",
            code=lambda_.Code.from_inline(
                open(os.path.join(PWD, "afc_lambdas", "delete_resources.py")).read()
            ),
            role=afc_role,
            timeout=core.Duration.seconds(900),
        )

        self.lambdas.append(delete_afc_resources_lambda)

        delete_afc_resources_step = tasks.LambdaInvoke(
            self,
            "DeleteAfcResourcesStep",
            lambda_function=delete_afc_resources_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        delete_afc_resources_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=[
                "ResourceNotFoundException",
                "ResourceInUseException",
                "ResourcePendingException",
            ],
        )

        #
        # SNS EMAIL
        #
        sns_afc_email_lambda = lambda_.Function(
            self,
            f"{construct_id}-SnsAfcEmailLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            environment={"TOPIC_ARN": topic.topic_arn},
            code=self.make_afc_email_inline_code(),
            handler="index.lambda_handler",
            role=afc_role,
        )

        self.lambdas.append(sns_afc_email_lambda)

        sns_afc_email_step = tasks.LambdaInvoke(
            self,
            "SnsAfcEmailStep",
            lambda_function=sns_afc_email_lambda,
            payload=sfn.TaskInput.from_object({"input": sfn.JsonPath.string_at("$")}),
        )

        #
        # State machine
        #
        definition = (
            prepare_step.next(create_predictor_step)
            .next(create_forecast_step)
            .next(create_predictor_backtest_export_step)
            .next(create_forecast_export_step)
            .next(postprocess_step)
            .next(delete_afc_resources_step)
            .next(sns_afc_email_step)
        )

        state_machine = sfn.StateMachine(
            self,
            "AfaSsmAfcStateMachine",
            state_machine_name=f"{construct_id}-AfcStateMachine",
            definition=definition,
            timeout=core.Duration.hours(24),
        )

        ssm.StringParameter(
            self,
            "AfaSsmAfcStateMachineArn",
            string_value=state_machine.state_machine_arn,
            parameter_name="AfaAfcStateMachineArn",
        )

        # add cfn-nag linting exceptions
        for lm in self.lambdas:
            lm.node.default_child.cfn_options.metadata = {
                "cfn_nag": {
                    "rules_to_suppress": [
                        {
                            "id": "W58",
                            "reason": "Role has permissions to write to CW logs",
                        },
                        {
                            "id": "W89",
                            "reason": "Function does not access VPC resources",
                        },
                        {
                            "id": "W92",
                            "reason": "Function is not intended to be run concurrently",
                        },
                    ]
                }
            }

    def make_nb_lcc_oncreate(self, construct_id):
        """Make the OnCreate script of the lifecycle configuration"""

        script_str = dedent(
            f"""
        #!/bin/bash
        set -x

        time sudo -u ec2-user -i <<'EOF'
        #!/bin/bash
        set -x
        unset SUDO_UID

        # install miniconda into ~/SageMaker/miniconda, which will make it
        # persistent
        CONDA_DIR=~/SageMaker/miniconda/

        mkdir -p "$CONDA_DIR"

        wget \
        -q https://repo.anaconda.com/miniconda/Miniconda3-py39_4.10.3-Linux-x86_64.sh \
        -O "$CONDA_DIR/miniconda.sh"
        bash "$CONDA_DIR/miniconda.sh" -b -u -p "$CONDA_DIR"
        rm -rf "$CONDA_DIR/miniconda.sh"

        # use local miniconda distro
        source "$CONDA_DIR/bin/activate"

        # install custom conda environment(s)
        conda create -y -q -p $CONDA_DIR/envs/py39 python=3.9 nodejs=16
        conda activate $CONDA_DIR/envs/py39

        # install the aws-cdk cli tool (req. for running `cdk deploy ...`)
        npm i -g aws-cdk@2.17.0

        # switch to SageMaker directory for persistance
        cd ~/SageMaker/

        # install sfs (required by the dashboard code)
        git clone https://github.com/aws-samples/simple-forecast-solution.git
        cd ./simple-forecast-solution ;
        git checkout {self.afa_branch.value_as_string}
        pip install -q --use-deprecated=legacy-resolver -e .

        # install lambdamap (required by the dashboard code)
        git clone https://github.com/aws-samples/lambdamap.git
        cd ./lambdamap/
        git checkout {self.lambdamap_branch.value_as_string}
        pip install -q --use-deprecated=legacy-resolver -e .

        EOF
        """
        )

        lcc = (
            sm.CfnNotebookInstanceLifecycleConfig.NotebookInstanceLifecycleHookProperty(
                content=core.Fn.base64(script_str)
            )
        )

        return lcc

    def make_nb_lcc_onstart(self, notebook_instance_name, sns_lambda_function_name):
        """Make the OnStart script of the lifecycle configuration."""
        # nosec below to ignore B608 as this is not an SQL query
        script_str = dedent(  # nosec
            f"""
        #!/bin/bash

        time sudo -u ec2-user -i <<'EOF'
        #!/bin/bash
        unset SUDO_UID

        # ensure that the local conda distribution is used
        CONDA_DIR=~/SageMaker/miniconda/
        source "$CONDA_DIR/bin/activate"

        conda activate $CONDA_DIR/envs/py39
        conda install ipykernel

        # Get the notebook URL
        NOTEBOOK_URL=$(aws sagemaker describe-notebook-instance \
            --notebook-instance-name {notebook_instance_name} \
            --query "Url" \
            --output text)
        DASHBOARD_URL=$NOTEBOOK_URL/proxy/8501/

        # Get the instructions ipynb notebook URL (email to user)
        LANDING_PAGE_URL=https://$NOTEBOOK_URL/lab/tree/Landing_Page.ipynb

        cd ~/SageMaker/simple-forecast-solution/

        # update w/ the latest AFA code
        git reset --hard
        git pull --all

        cp -rp ./cdk/workspace/* ~/SageMaker/

        # Update the url in the landing page
        sed -i 's|INSERT_URL_HERE|https:\/\/'$DASHBOARD_URL'|' ~/SageMaker/Landing_Page.ipynb

        export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

        #
        # start the streamlit demo  on port 8501 of the notebook instance,
        # it will be viewable at:
        #
        # - https://<NOTEBOOK_URL>/proxy/8501/
        #
        nohup streamlit run --server.port 8501 \
            --theme.base light \
            --server.headless true \
            --browser.gatherUsageStats false -- ./afa/app/app.py \
            --local-dir ~/SageMaker/ --landing-page-url $LANDING_PAGE_URL &

        # Send SNS email
        aws lambda invoke --function-name {sns_lambda_function_name} \
            --payload '{{"landing_page_url": "'$LANDING_PAGE_URL'", "dashboard_url": "'$DASHBOARD_URL'"}}' ./SnsEmailLambda.out # noqa:E501,W605
        EOF
        """
        )

        lcc = (
            sm.CfnNotebookInstanceLifecycleConfig.NotebookInstanceLifecycleHookProperty(
                content=core.Fn.base64(script_str)
            )
        )

        return lcc

    def make_nb_lcc(
        self, construct_id, notebook_instance_name, sns_lambda_function_name
    ):
        """ """

        lcc_oncreate = self.make_nb_lcc_oncreate(construct_id)
        lcc_onstart = self.make_nb_lcc_onstart(
            notebook_instance_name, sns_lambda_function_name
        )

        lcc = sm.CfnNotebookInstanceLifecycleConfig(
            self,
            "NotebookLifecycleConfig",
            on_create=[lcc_oncreate],
            on_start=[lcc_onstart],
        )

        return lcc

    def make_dashboard_ready_email_inline_code(self):
        """This is the lambda that sends the notification email to the user once
        the dashboard is deployed, it contains the URL to the landing page
        sagemaker notebook.

        """

        inline_code_str = dedent(
            """
        import os
        import re
        import json
        import boto3
        import textwrap

        def lambda_handler(event, context):
            landing_page_url = (
                "https://" + re.sub(r"^(https*://)", "", event["landing_page_url"])
            )
            dashboard_url = (
                "https://" + re.sub(r"^(https*://)", "", event["dashboard_url"])
            )

            client = boto3.client("sns")
            response = client.publish(
                TopicArn=os.environ["TOPIC_ARN"],
                Subject="Your AFA Dashboard is Ready!",
                Message=textwrap.dedent(f'''
                Congratulations!

                Amazon Forecast Accelerator (AFA) has been successfully deployed
                into your AWS account.

                Visit the landing page below to get started:
                ‣ {landing_page_url}

                Sincerely,
                The Amazon Forecast Accelerator Team
                ‣ https://github.com/aws-samples/simple-forecast-solution
                '''))

            return response
        """
        )

        return lambda_.Code.from_inline(inline_code_str)

    def make_afc_email_inline_code(self):
        """This is the lambda that sends the notification email to the user once
        the dashboard is deployed, it contains the URL to the landing page
        sagemaker notebook.

        """

        inline_code_str = dedent(
            """
        import os
        import re
        import json
        import boto3

        from textwrap import dedent

        def lambda_handler(event, context):
            payload = event["input"]["Payload"]
            client = boto3.client("sns")

            response = client.publish(
                TopicArn=os.environ["TOPIC_ARN"],
                Subject="[AFA] Your ML Forecast job has completed!",
                Message=dedent(f'''
                Hi!

                Your AFA Machine Learning Forecast job has completed.

                You can then download the forecast files using the
                "Export Machine Learning Forecasts" button in the
                "Machine Learning Forecasts" section of your report
                via the dashboard.

                Sincerely,
                The Amazon Forecast Accelerator Team
                ‣ https://github.com/aws-samples/simple-forecast-solution
                '''))
            return response
        """
        )

        return lambda_.Code.from_inline(inline_code_str)
