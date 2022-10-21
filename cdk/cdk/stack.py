import os

from textwrap import dedent
from constructs import Construct
import aws_cdk as core
from aws_cdk import (
    aws_s3 as s3,
    aws_ssm as ssm,
    aws_iam as iam,
    aws_sagemaker as sm,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_lambda as lambda_,
    aws_ec2 as ec2,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    Stack,
    aws_codebuild as codebuild
)

PWD = os.path.dirname(os.path.realpath(__file__))

TAG_NAME = "Project"
TAG_VALUE = "Afa"


class AfaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(
            scope,
            construct_id,
            **{"description": "Amazon Forecast Accelerator (uksb-1s7c5ojr9)"},
        )
        email_address = core.CfnParameter(self, "emailAddress",
                description="(Required) An e-mail address with which to receive "
                "deployment notifications.")

        instance_type = core.CfnParameter(self, "instanceType",
                default="ml.t2.medium",
                description="(Required) SageMaker Notebook instance type on which to host "
                "the AFA dashboard (e.g. ml.t2.medium, ml.t3.xlarge, ml.t3.2xlarge, ml.m4.4xlarge)")

        self.afa_branch = kwargs.get("afa_branch", "main")
        self.lambdamap_branch = kwargs.get("lambdamap_branch", "main")
        self.lambdamap_function_name = kwargs.get("lambdamap_function_name", "AfaLambdaMapFunction")

        #
        # S3 Bucket
        #
        bucket = s3.Bucket(self, "Bucket", auto_delete_objects=False,
            removal_policy=core.RemovalPolicy.DESTROY,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL)

        #
        # SSM Parameter Store
        #
        ssm_s3_bucket_path_param = ssm.StringParameter(self,
                "AfaSsmS3Bucket",
                string_value=bucket.bucket_name,
                parameter_name="AfaS3Bucket")

        ssm_s3_input_path_param = ssm.StringParameter(self,
                "AfaSsmS3InputPath",
                string_value=f"s3://{bucket.bucket_name}/input/",
                parameter_name="AfaS3InputPath")

        ssm_s3_output_path_param = ssm.StringParameter(self,
                "AfaSsmS3OutputPath",
                string_value=f"s3://{bucket.bucket_name}/afc-exports/",
                parameter_name="AfaS3OutputPath")

        #
        # SNS topic for email notification
        #
        topic = \
            sns.Topic(self, f"NotificationTopic",
                topic_name=f"{construct_id}-NotificationTopic")

        topic.add_subscription(
            subscriptions.EmailSubscription(email_address.value_as_string))

        self.topic = topic

        sns_lambda_role = iam.Role(
            self,
            f"SnsEmailLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSFullAccess")
            ])

        self.sns_lambda_role = sns_lambda_role

        sns_lambda = lambda_.Function(self,
            f"SnsEmailLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            environment={"TOPIC_ARN": f"arn:aws:sns:{self.region}:{self.account}:{topic.topic_name}"},
            code=self.make_dashboard_ready_email_inline_code(),
            handler="index.lambda_handler",
            role=sns_lambda_role)

        #
        # Notebook lifecycle configuration
        #
        notebook_instance_name = f"{construct_id}-NotebookInstance"
        lcc = self.make_nb_lcc(construct_id, notebook_instance_name,
                sns_lambda.function_name)
        #
        # Notebook role
        #
        sm_role = iam.Role(
            self,
            f"NotebookRole",
            assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"))

        sm_policy = \
            iam.Policy(
                self,
                "SmPolicy",
                roles=[sm_role],
                statements=[
                    # Lambda
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "lambda:*",
                        ],
                        resources=[
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{self.lambdamap_function_name}",
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{core.Aws.STACK_NAME}*",
                        ]
                    ),

                    # S3
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "s3:*"
                        ],
                        resources=[
                            f"arn:aws:s3:::{construct_id.lower()}*",
                        ]
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
                            "sagemaker:AddTags",
                            "sagemaker:DeleteTags",
                            "sagemaker:ListTags",

                        ],
                        resources=[
                            f"arn:aws:sagemaker:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:notebook-instance/{construct_id.lower()}*",
                            f"arn:aws:sagemaker:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:notebook-instance-lifecycle-config/notebooklifecycleconfig*",
                        ]
                    ),

                    # Step Functions
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "states:*"
                        ],
                        resources=[
                            f"arn:aws:states:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:*:{core.Aws.STACK_NAME}*",
                        ]
                    ),

                    # SSM
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "ssm:*"
                        ],
                        resources=[
                            f"arn:aws:ssm:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:parameter/AfaS3Bucket",
                            f"arn:aws:ssm:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:parameter/AfaS3InputPath",
                            f"arn:aws:ssm:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:parameter/AfaS3OutputPath",
                            f"arn:aws:ssm:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:parameter/AfaAfcStateMachineArn",
                        ]
                    ),
                ]
            )

        #
        # Notebook instance
        #
        sm.CfnNotebookInstance(
            self,
            f"NotebookInstance",
            role_arn=sm_role.role_arn,
            instance_type=instance_type.value_as_string,
            notebook_instance_name=notebook_instance_name,
            volume_size_in_gb=16,
            lifecycle_config_name=lcc.attr_notebook_instance_lifecycle_config_name,
            )
        
        # AFC/Lambda role
        afc_role = \
            iam.Role(
            self,
            f"AfcRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("forecast.amazonaws.com"),
                iam.ServicePrincipal("lambda.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonForecastFullAccess"),
            ])

        afc_policy = \
            iam.Policy(
                self,
                "AfcPolicy",
                roles=[afc_role],
                statements=[
                    # Lambda
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "lambda:*",
                        ],
                        resources=[
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{self.lambdamap_function_name}",
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{core.Aws.STACK_NAME}*",
                        ]
                    ),

                    # S3
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "s3:*"
                        ],
                        resources=[
                            f"arn:aws:s3:::{construct_id.lower()}*",
                        ]
                    ),

                    # Logging
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "logs:*"
                        ],
                        resources=[
                            f"arn:aws:logs:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:log-group:/aws/lambda/{core.Aws.STACK_NAME}*"
                        ]
                    ),

                    # SNS
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "sns:*"
                        ],
                        resources=[
                            f"arn:aws:sns:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:{core.Aws.STACK_NAME}*"
                        ]
                    ),
                ]
            )
        
        fail_state = sfn.Fail(self, "Fail")
        succeed_state = sfn.Succeed(self, "Succeed")

        #
        # PREPARE DATA
        #
        prepare_lambda = \
            lambda_.Function(
                self,
                "PrepareLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.prepare_handler",
                code=lambda_.Code.from_inline(open(os.path.join(PWD, "afc_lambdas", "prepare.py")).read()),
                environment={
                    "AFC_ROLE_ARN": afc_role.role_arn
                },
                role=afc_role,
                timeout=core.Duration.seconds(900)
            )

        prepare_step = \
            tasks.LambdaInvoke(
                self,
                "PrepareDataStep",
                lambda_function=prepare_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        #
        # CREATE PREDICTOR
        #
        create_predictor_lambda = \
            lambda_.Function(
                self,
                "CreatedPredictorLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.create_predictor_handler",
                code=lambda_.Code.from_inline(open(os.path.join(PWD, "afc_lambdas", "create_predictor.py")).read()),
                environment={
                    "AFC_ROLE_ARN": afc_role.role_arn
                },
                role=afc_role,
                timeout=core.Duration.seconds(900))

        create_predictor_step = \
            tasks.LambdaInvoke(
                self,
                "CreatePredictorStep",
                lambda_function=create_predictor_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        create_predictor_step.add_retry(
                backoff_rate=1.05,
                interval=core.Duration.seconds(60),
                max_attempts=1000,
                errors=["ResourceNotFoundException",
                        "ResourceInUseException",
                        "ResourcePendingException"])

        #
        # CREATE FORECAST
        #
        create_forecast_lambda = \
            lambda_.Function(
                self,
                "CreatedForecastLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.create_forecast_handler",
                code=lambda_.Code.from_inline(
                    open(os.path.join(PWD, "afc_lambdas", "create_forecast.py")).read()),
                role=afc_role,
                timeout=core.Duration.seconds(900))

        create_forecast_step = \
            tasks.LambdaInvoke(
                self,
                "CreateforecastStep",
                lambda_function=create_forecast_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        create_forecast_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceNotFoundException",
                    "ResourceInUseException",
                    "ResourcePendingException"])

        #
        # CREATE FORECAST EXPORT
        #
        create_forecast_export_lambda = \
            lambda_.Function(
                self,
                "CreateExportLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.create_forecast_export_handler",
                code=lambda_.Code.from_inline(
                    open(os.path.join(PWD, "afc_lambdas", "create_export.py")).read()),
                environment={
                    "AFC_ROLE_ARN": afc_role.role_arn
                },
                role=afc_role,
                timeout=core.Duration.seconds(900))

        create_forecast_export_step = \
            tasks.LambdaInvoke(
                self,
                "CreateExportStep",
                lambda_function=create_forecast_export_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        create_forecast_export_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceInUseException",
                    "ResourcePendingException"])

        #
        # BACKTEST EXPORT FILE(s)
        #
        create_predictor_backtest_export_lambda = \
            lambda_.Function(
                self,
                "CreatePredictorBacktestExportLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.create_predictor_backtest_export_handler",
                code=lambda_.Code.from_inline(
                    open(os.path.join(PWD, "afc_lambdas",
                            "create_predictor_backtest_export.py")).read()),
                environment={
                    "AFC_ROLE_ARN": afc_role.role_arn
                },
                role=afc_role,
                timeout=core.Duration.seconds(900))

        create_predictor_backtest_export_step = \
            tasks.LambdaInvoke(
                self,
                "CreatePredictorBacktestExportStep",
                lambda_function=create_predictor_backtest_export_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        create_predictor_backtest_export_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceInUseException",
                    "ResourcePendingException"])

        #
        # POSTPROCESS FORECAST EXPORT FILE(s)
        #
        postprocess_lambda = \
            lambda_.Function(self, 
                f"PostProcessLambda",
                code=lambda_.EcrImageCode \
                            .from_asset_image(
                    directory=os.path.join(PWD, "afc_lambdas", "postprocess")),
                runtime=lambda_.Runtime.FROM_IMAGE,
                handler=lambda_.Handler.FROM_IMAGE,
                memory_size=3000,
                role=afc_role,
                timeout=core.Duration.seconds(900))

        postprocess_step = \
            tasks.LambdaInvoke(
                self,
                "PostProcessStep",
                lambda_function=postprocess_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        postprocess_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(30),
            max_attempts=2000,
            errors=["NoFilesFound",
                    "ResourceInUseException",
                    "ResourcePendingException"])

        # DELETE AFC RESOURCES
        delete_afc_resources_lambda = \
            lambda_.Function(
                self,
                "DeleteAfcResourcesLambda",
                runtime=lambda_.Runtime.PYTHON_3_8,
                handler="index.delete_afc_resources_handler",
                code=lambda_.Code.from_inline(
                    open(os.path.join(PWD, "afc_lambdas", "delete_resources.py")).read()),
                role=afc_role,
                timeout=core.Duration.seconds(900))
        
        delete_afc_resources_step = \
            tasks.LambdaInvoke(
                self,
                "DeleteAfcResourcesStep",
                lambda_function=delete_afc_resources_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        delete_afc_resources_step.add_retry(
            backoff_rate=1.1,
            interval=core.Duration.seconds(60),
            max_attempts=2000,
            errors=["ResourceNotFoundException",
                    "ResourceInUseException",
                    "ResourcePendingException"])

        #
        # SNS EMAIL
        #
        sns_afc_email_lambda = \
            lambda_.Function(self, f"{construct_id}-SnsAfcEmailLambda",
            runtime=lambda_.Runtime.PYTHON_3_8,
            environment={"TOPIC_ARN": topic.topic_arn},
            code=self.make_afc_email_inline_code(),
            handler="index.lambda_handler",
            role=afc_role)

        sns_afc_email_step = \
            tasks.LambdaInvoke(
                self,
                "SnsAfcEmailStep",
                lambda_function=sns_afc_email_lambda,
                payload=sfn.TaskInput.from_object({
                    "input": sfn.JsonPath.string_at("$")
                })
            )

        #
        # State machine
        #
        definition = prepare_step.next(create_predictor_step) \
                                 .next(create_forecast_step) \
                                 .next(create_predictor_backtest_export_step) \
                                 .next(create_forecast_export_step) \
                                 .next(postprocess_step) \
                                 .next(delete_afc_resources_step) \
                                 .next(sns_afc_email_step)

        state_machine = sfn.StateMachine(self,
            "AfaSsmAfcStateMachine",
            state_machine_name=f"{construct_id}-AfcStateMachine",
            definition=definition,
            timeout=core.Duration.hours(24))

        ssm_state_machine_param = ssm.StringParameter(self,
            "AfaSsmAfcStateMachineArn",
            string_value=state_machine.state_machine_arn,
            parameter_name="AfaAfcStateMachineArn")

    def make_nb_lcc_oncreate(self, construct_id):
        """Make the OnCreate script of the lifecycle configuration

        """

        script_str = dedent(f"""
        #!/bin/bash

        time sudo -u ec2-user -i <<'EOF'
        #!/bin/bash
        unset SUDO_UID

        # install miniconda into ~/SageMaker/miniconda, which will make it
        # persistent
        CONDA_DIR=~/SageMaker/miniconda/

        mkdir -p "$CONDA_DIR"

        wget -q https://repo.anaconda.com/miniconda/Miniconda3-py39_4.10.3-Linux-x86_64.sh \
            -O "$CONDA_DIR/miniconda.sh"
        bash "$CONDA_DIR/miniconda.sh" -b -u -p "$CONDA_DIR"
        rm -rf "$CONDA_DIR/miniconda.sh"

        # use local miniconda distro
        source "$CONDA_DIR/bin/activate"

        # install custom conda environment(s)
        conda create -y -q -n py39 python=3.9 nodejs=16
        conda activate py39

        # install the aws-cdk cli tool (req. for running `cdk deploy ...`)
        npm i -g aws-cdk@2.17.0

        # switch to SageMaker directory for persistance
        cd ~/SageMaker/

        # install sfs (required by the dashboard code)
        git clone https://github.com/aws-samples/simple-forecast-solution.git
        cd ./simple-forecast-solution ;
        git checkout {self.afa_branch}
        pip install -q --use-deprecated=legacy-resolver -e .

        # install lambdamap (required by the dashboard code)
        git clone https://github.com/aws-samples/lambdamap.git
        cd ./lambdamap/
        git checkout {self.lambdamap_branch}
        pip install -q --use-deprecated=legacy-resolver -e .

        EOF
        """)

        lcc = \
            sm.CfnNotebookInstanceLifecycleConfig \
              .NotebookInstanceLifecycleHookProperty(
                  content=core.Fn.base64(script_str))

        return lcc

    def make_nb_lcc_onstart(self, notebook_instance_name, sns_lambda_function_name):
        """Make the OnStart script of the lifecycle configuration.

        """

        script_str = dedent(f"""
        #!/bin/bash

        time sudo -u ec2-user -i <<'EOF'
        #!/bin/bash
        unset SUDO_UID

        # ensure that the local conda distribution is used
        CONDA_DIR=~/SageMaker/miniconda/
        source "$CONDA_DIR/bin/activate"

        # make the custom conda environments available as kernels in the
        # jupyter notebooks
        for env in $CONDA_DIR/envs/* ; do
            basename=$(basename "$env")
            source activate "$basename"
            python -m ipykernel install --user --name "$basename" \
                --display-name "Custom ($basename)"
        done

        conda activate py39

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
            --browser.gatherUsageStats false -- ./afa/app/app.py \
            --local-dir ~/SageMaker/ --landing-page-url $LANDING_PAGE_URL &

        # Send SNS email
        aws lambda invoke --function-name {sns_lambda_function_name} \
            --payload '{{"landing_page_url": "'$LANDING_PAGE_URL'", "dashboard_url": "'$DASHBOARD_URL'"}}' \
            /dev/stdout
        EOF

        # install jupyter-server-proxy
        source /home/ec2-user/anaconda3/bin/activate JupyterSystemEnv

        pip install --use-deprecated=legacy-resolver --upgrade pip
        pip uninstall -q --yes nbserverproxy || true
        pip install --use-deprecated=legacy-resolver -q --upgrade jupyter-server-proxy

        # restart the jupyterlab server
        initctl restart jupyter-server --no-wait
        """)

        lcc = sm.CfnNotebookInstanceLifecycleConfig \
                .NotebookInstanceLifecycleHookProperty(
                    content=core.Fn.base64(script_str))

        return lcc

    def make_nb_lcc(self, construct_id, notebook_instance_name, sns_lambda_function_name):
        """
        """

        lcc_oncreate = self.make_nb_lcc_oncreate(construct_id)
        lcc_onstart = self.make_nb_lcc_onstart(notebook_instance_name,
            sns_lambda_function_name)

        lcc = sm.CfnNotebookInstanceLifecycleConfig(
            self,
            f"NotebookLifecycleConfig",
            on_create=[lcc_oncreate],
            on_start=[lcc_onstart])

        return lcc
        
    def make_dashboard_ready_email_inline_code(self):
        """This is the lambda that sends the notification email to the user once
        the dashboard is deployed, it contains the URL to the landing page
        sagemaker notebook.

        """

        inline_code_str = dedent("""
        import os
        import re
        import json
        import boto3
        import textwrap

        def lambda_handler(event, context):
            landing_page_url = "https://" + re.sub(r"^(https*://)", "", event["landing_page_url"])
            dashboard_url = "https://" + re.sub(r"^(https*://)", "", event["dashboard_url"])

            client = boto3.client("sns")
            response = client.publish(
                TopicArn=os.environ["TOPIC_ARN"],
                Subject="Your AFA Dashboard is Ready!",
                Message=textwrap.dedent(f'''
                Congratulations!
                
                Amazon Forecast Accelerator (AFA) has been successfully deployed into your AWS account.
                
                Visit the landing page below to get started:
                ‣ {landing_page_url}
                
                Sincerely,
                The Amazon Forecast Accelerator Team
                ‣ https://github.com/aws-samples/simple-forecast-solution
                '''))
            
            return response
        """)

        return lambda_.Code.from_inline(inline_code_str)

    def make_afc_email_inline_code(self):
        """This is the lambda that sends the notification email to the user once
        the dashboard is deployed, it contains the URL to the landing page
        sagemaker notebook.

        """

        inline_code_str = dedent("""
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

                You can then download the forecast files using the "Export Machine Learning Forecasts"
                button in the "Machine Learning Forecasts" section of your report via the dashboard.

                Sincerely,
                The Amazon Forecast Accelerator Team
                ‣ https://github.com/aws-samples/simple-forecast-solution
                '''))
            return response
        """)

        return lambda_.Code.from_inline(inline_code_str)
