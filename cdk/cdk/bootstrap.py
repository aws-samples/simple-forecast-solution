#!/usr/bin/env python3
import os

from textwrap import dedent
from aws_cdk import (
    core,
    core as cdk,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_codebuild as codebuild,
)

AFA_REPO_URL = "https://github.com/aws-samples/simple-forecast-solution.git"
LAMBDAMAP_REPO_URL = "https://github.com/aws-samples/lambdamap.git"

LAMBDAMAP_STACK_NAME = "AfaLambdaMapStack"
LAMBDAMAP_FUNCTION_NAME = "AfaLambdaMapFunction"

TAG_NAME = "Project"
TAG_VALUE = "Afa"

# The lambda function to start a build of the codebuild project 
INLINE_CODEBUILD_LAMBDA = dedent("""
import os
import json
import boto3
import cfnresponse

def lambda_handler(event, context):
    client = boto3.client("codebuild")
    client.start_build(projectName=os.environ["CODEBUILD_PROJECT_NAME"])
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {},
        "CustomResourcePhysicalID")
    return
""")


class BootstrapStack(core.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        """
        """
        super().__init__(scope, construct_id)

        afa_branch = kwargs.get("afa_branch", "main")
        lambdamap_branch = kwargs.get("lambdamap_branch", "main")
        self.afa_stack_name = kwargs.get("afa_stack_name", "AfaStack")

        email_address = core.CfnParameter(self, "emailAddress",
                allowed_pattern=".+",
                description="(Required) An e-mail address with which to receive "
                "deployment notifications.")

        instance_type = core.CfnParameter(self, "instanceType",
                default="ml.t2.medium",
                description="(Required) SageMaker Notebook instance type on which to host "
                "the AFA dashboard (e.g. ml.t2.medium, ml.t3.xlarge, ml.t3.2xlarge, ml.m4.4xlarge)")
        
        lambdamap_function_name = core.CfnParameter(self, "lambdamapFunctionName",
                default=LAMBDAMAP_FUNCTION_NAME)
        
        codebuild_project_id = "AfaCodeBuildProject"

        # Add any policies needed to deploy the main stack
        codebuild_role = iam.Role(
            self,
            f"CodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeBuildDeveloperAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPowerUser"),
            ],
        )

        policy = \
            iam.Policy(
                self,
                "CodeBuildPolicy",
                roles=[codebuild_role],
                statements=[
                    # CloudFormation
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "cloudformation:*",
                        ],
                        resources=[
                            f"arn:aws:cloudformation:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:stack/{core.Aws.STACK_NAME}*",
                            f"arn:aws:cloudformation:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:stack/{self.afa_stack_name}*",
                            f"arn:aws:cloudformation:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:stack/{LAMBDAMAP_STACK_NAME}*",
                            f"arn:aws:cloudformation:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:stack/CDKToolkit*",
                        ]
                    ),
                    
                    # IAM
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "iam:DeletePolicy",
                            "iam:CreateRole",
                            "iam:AttachRolePolicy",
                            "iam:PutRolePolicy",
                            "iam:PassRole",
                            "iam:DetachRolePolicy",
                            "iam:DeleteRolePolicy",
                            "iam:GetRole",
                            "iam:GetPolicy",
                            "iam:UpdateRoleDescription",
                            "iam:DeleteRole",
                            "iam:CreatePolicy",
                            "iam:UpdateRole",
                            "iam:GetRolePolicy",
                            "iam:DeletePolicyVersion",
                            "iam:TagRole",
                            "iam:TagPolicy"      
                        ],
                        resources=[
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/{core.Aws.STACK_NAME}*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/{self.afa_stack_name}*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/{LAMBDAMAP_STACK_NAME}*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/cdk-*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:policy/{core.Aws.STACK_NAME}*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:policy/{self.afa_stack_name}*",
                            f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:policy/{LAMBDAMAP_STACK_NAME}*",
                            f"arn:aws:lambda:*:{core.Aws.ACCOUNT_ID}:policy/{core.Aws.STACK_NAME}*",
                            f"arn:aws:lambda:*:{core.Aws.ACCOUNT_ID}:policy/{self.afa_stack_name}*",
                            f"arn:aws:lambda:*:{core.Aws.ACCOUNT_ID}:policy/{LAMBDAMAP_STACK_NAME}*",
                        ]
                    ),

                    # CodeBuild logs
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "logs:*"
                        ],
                        resources=[
                            f"arn:aws:logs:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:log-group:/aws/codebuild/{codebuild_project_id}*"
                        ]
                    ),

                    # Lambda
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "lambda:*",
                        ],
                        resources=[
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{lambdamap_function_name.value_as_string}",
                            f"arn:aws:lambda:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:function:{self.afa_stack_name}*",
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
                            f"arn:aws:sagemaker:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:notebook-instance/{self.afa_stack_name.lower()}*",
                            f"arn:aws:sagemaker:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:notebook-instance-lifecycle-config/notebooklifecycleconfig*",
                        ]
                    ),

                    # SNS
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "sns:*"
                        ],
                        resources=[
                            f"arn:aws:sns:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:{self.afa_stack_name}-NotificationTopic"
                        ]
                    ),

                    # S3
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "s3:*"
                        ],
                        resources=[
                            f"arn:aws:s3:::cdk-*",
                            f"arn:aws:s3:::cdktoolkit-*",
                            f"arn:aws:s3:::afastack*",
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
                            f"arn:aws:ssm:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:parameter/cdk-bootstrap/*",
                        ]
                    ),

                    # Step Functions
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "states:*"
                        ],
                        resources=[
                            f"arn:aws:states:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:stateMachine:{self.afa_stack_name}*",
                        ]
                    ),

                    # ECR
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "ec2:DescribeAvailabilityZones",
                            "sts:GetCallerIdentity",
                            "ecr:GetAuthorizationToken",
                            "ecr:BatchCheckLayerAvailability",
                            "ecr:GetDownloadUrlForLayer",
                            "ecr:GetRepositoryPolicy",
                            "ecr:DescribeRepositories",
                            "ecr:ListImages",
                            "ecr:DescribeImages",
                            "ecr:BatchGetImage",
                            "ecr:GetLifecyclePolicy",
                            "ecr:GetLifecyclePolicyPreview",
                            "ecr:ListTagsForResource",
                            "ecr:DescribeImageScanFindings",
                            "ecr:InitiateLayerUpload",
                            "ecr:UploadLayerPart",
                            "ecr:CompleteLayerUpload",
                            "ecr:PutImage",
                            "ecr:SetRepositoryPolicy",
                            "ecr:CreateRepository",
                            "ecr:PutImageScanningConfiguration",
                            "ecr:DeleteRepository",
                            "ecr:TagResource",
                            "ecr:UntagResource"
                        ],
                        resources=[
                            f"*"
                        ]
                    )
                ]
            )

        codebuild_project = \
            codebuild.Project(self,
                codebuild_project_id,
                environment=codebuild.BuildEnvironment(
                    privileged=True,
                    build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2_3
                ),
                environment_variables={
                    "LAMBDAMAP_STACK_NAME": codebuild.BuildEnvironmentVariable(value=LAMBDAMAP_STACK_NAME),
                    "LAMBDAMAP_FUNCTION_NAME": codebuild.BuildEnvironmentVariable(value=LAMBDAMAP_FUNCTION_NAME),
                    "EMAIL": codebuild.BuildEnvironmentVariable(value=email_address.value_as_string),
                    "INSTANCE_TYPE": codebuild.BuildEnvironmentVariable(value=instance_type.value_as_string),
                    "AFA_STACK_NAME": codebuild.BuildEnvironmentVariable(value=self.afa_stack_name),
                },
                # define the deployment steps here
                build_spec=codebuild.BuildSpec.from_object(
                    {
                        "version": "0.2",
                        "phases": {
                            "install": {
                                "runtime-versions": {
                                    "python": "3.9",
                                    "nodejs": "16"
                                },
                                "commands": [
                                    f"""export CDK_TAGS=$(aws cloudformation describe-stacks --stack-name {core.Aws.STACK_NAME} --query Stacks[0].Tags | python -c 'import sys, json; print(" ".join("--tags " + d["Key"] + "=" + d["Value"] for d in json.load(sys.stdin)))')""",
                                    "export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)",
                                    "export BOOTSTRAP_URL=aws://$AWS_ACCOUNT_ID/$AWS_DEFAULT_REGION",
                                    "npm i --silent --quiet --no-progress -g aws-cdk@2.17.0",
                                    "(( [[ -n \"CDK_TAGS\" ]] ) && ( cdk bootstrap ${BOOTSTRAP_URL} )) || ( cdk bootstrap ${BOOTSTRAP_URL} )"
                                ]
                            },
                            "pre_build": {
                                "commands": []
                            },
                            "build": {
                                "commands": [
                                    f"git clone {LAMBDAMAP_REPO_URL}",
                                    "cd lambdamap/",
                                    f"git checkout {lambdamap_branch}",
                                    'make deploy STACK_NAME=$LAMBDAMAP_STACK_NAME CDK_TAGS="$CDK_TAGS" '
                                    'FUNCTION_NAME=$LAMBDAMAP_FUNCTION_NAME '
                                    f"EXTRA_CMDS=\"'git clone {AFA_REPO_URL} ; cd ./simple-forecast-solution/ ; git checkout {afa_branch} ; pip install --use-deprecated=legacy-resolver -e .'\"",
                                    "cd ..",
                                    f"git clone {AFA_REPO_URL}",
                                    "cd simple-forecast-solution/",
                                    f"git checkout {afa_branch}",
                                    f'make deploy-ui EMAIL=$EMAIL INSTANCE_TYPE=$INSTANCE_TYPE AFA_STACK_NAME=$AFA_STACK_NAME CDK_TAGS="$CDK_TAGS" '
                                ]
                            },
                            "post_build": {
                                "commands": [
                                    # add post-deployment tests and checks here
                                    "echo 'Deploy Completed'"
                                ]
                            }
                        }
                    }
                ),
                role=codebuild_role
            )

        lambda_role = iam.Role(
            self, "LambdaRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lambda.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeBuildDeveloperAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        # this lambda function will trigger the cdk deployment via codebuild
        lambda_func = lambda_.Function(
            self, "LambdaFunction",
            runtime=lambda_.Runtime.PYTHON_3_8,
            code=lambda_.Code.from_inline(INLINE_CODEBUILD_LAMBDA),
            handler="index.lambda_handler",
            environment={
                "CODEBUILD_PROJECT_NAME": codebuild_project.project_name
            },
            role=lambda_role
        )

        cust_resource = core.CustomResource(self, "CustomResource",
            service_token=lambda_func.function_arn)
        cust_resource.node.add_dependency(codebuild_project)

        return
    

if __name__ == "__main__":
    app = core.App()
    core.Tags.of(app).add(TAG_NAME, TAG_VALUE)
    stack = BootstrapStack(app, "AfaBootstrapStack")
    app.synth()
