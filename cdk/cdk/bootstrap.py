#!/usr/bin/env python3
from textwrap import dedent

import aws_cdk as core
from aws_cdk import Aws, Stack
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from constructs import Construct

AFA_REPO_URL = "https://github.com/aws-samples/simple-forecast-solution.git"
LAMBDAMAP_REPO_URL = "https://github.com/aws-samples/lambdamap.git"

LAMBDAMAP_STACK_NAME = "AfaLambdaMapStack"
LAMBDAMAP_FUNCTION_NAME = "AfaLambdaMapFunction"

TAG_NAME = "Project"
TAG_VALUE = "Afa"
RACC = f"{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}"

# The lambda function to start a build of the codebuild project
INLINE_CODEBUILD_LAMBDA = dedent(
    """
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
"""
)


class BootstrapStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """ """
        super().__init__(scope, construct_id)

        # self.lambdamap_branch = kwargs.get("lambdamap_branch", "main")
        self.afa_stack_name = kwargs.get("afa_stack_name", "AfaStack")

        #
        # CloudFormation input parameters
        #
        self.email_address = core.CfnParameter(
            self,
            "emailAddress",
            allowed_pattern=".+",
            description="(Required) An e-mail address with which to receive "
            "deployment notifications.",
        )

        self.instance_type = core.CfnParameter(
            self,
            "instanceType",
            default="ml.t2.medium",
            description="(Required) SageMaker Notebook instance type to host "
            "the AFA dashboard (e.g. ml.t2.medium, ml.t3.xlarge, ml.t3.2xlarge,"
            " ml.m4.4xlarge)",
        )

        self.lambdamap_function_name = core.CfnParameter(
            self, "lambdamapFunctionName", default=LAMBDAMAP_FUNCTION_NAME
        )

        self.lambdamap_branch = core.CfnParameter(
            self, "lambdamapBranch", default="main"
        )
        self.afa_branch = core.CfnParameter(self, "afaBranch", default="main")

        codebuild_project_id = "AfaCodeBuildProject"

        # Add any policies needed to deploy the main stack
        codebuild_role = iam.Role(
            self,
            "CodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AWSCodeBuildDeveloperAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonEC2ContainerRegistryPowerUser"
                ),
            ],
        )

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
                        f"arn:aws:cloudformation:{RACC}:stack/{core.Aws.STACK_NAME}*",
                        f"arn:aws:cloudformation:{RACC}:stack/{self.afa_stack_name}*",
                        f"arn:aws:cloudformation:{RACC}:stack/{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:cloudformation:{RACC}:stack/CDKToolkit*",
                    ],
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
                        "iam:TagPolicy",
                    ],
                    resources=[
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:role/" f"{Aws.STACK_NAME}*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:role/"
                        f"{self.afa_stack_name}*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:role/"
                        f"{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:role/cdk-*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:policy/" f"{Aws.STACK_NAME}*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:policy/"
                        f"{self.afa_stack_name}*",
                        f"arn:aws:iam::{Aws.ACCOUNT_ID}:policy/"
                        f"{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:lambda:*:{Aws.ACCOUNT_ID}:policy/"
                        f"{Aws.STACK_NAME}*",
                        f"arn:aws:lambda:*:{Aws.ACCOUNT_ID}:policy/"
                        f"{self.afa_stack_name}*",
                        f"arn:aws:lambda:*:{Aws.ACCOUNT_ID}:policy/"
                        f"{LAMBDAMAP_STACK_NAME}*",
                    ],
                ),
                # CodeBuild logs
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:*"],
                    resources=[
                        f"arn:aws:logs:{RACC}:log-group:/aws/codebuild/"
                        f"{codebuild_project_id}*"
                    ],
                ),
                # Lambda
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:*",
                    ],
                    resources=[
                        f"arn:aws:lambda:{RACC}:function:"
                        f"{self.lambdamap_function_name.value_as_string}",
                        f"arn:aws:lambda:{RACC}:function:" f"{self.afa_stack_name}*",
                    ],
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
                        "sagemaker:addTags",
                    ],
                    resources=[
                        f"arn:aws:sagemaker:{RACC}:notebook-instance/"
                        f"{self.afa_stack_name.lower()}*",
                        f"arn:aws:sagemaker:{RACC}:notebook-instance-lifecycle-config/"
                        "notebooklifecycleconfig*",
                    ],
                ),
                # SNS
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["sns:*"],
                    resources=[
                        f"arn:aws:sns:{RACC}:{self.afa_stack_name}-NotificationTopic"
                    ],
                ),
                # S3
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["s3:*"],
                    resources=[
                        "arn:aws:s3:::cdk-*",
                        "arn:aws:s3:::cdktoolkit-*",
                        "arn:aws:s3:::afastack*",
                    ],
                ),
                # SSM
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["ssm:*"],
                    resources=[
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3Bucket",
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3InputPath",
                        f"arn:aws:ssm:{RACC}:parameter/AfaS3OutputPath",
                        f"arn:aws:ssm:{RACC}:parameter/AfaAfcStateMachineArn",
                        f"arn:aws:ssm:{RACC}:parameter/cdk-bootstrap/*",
                    ],
                ),
                # Step Functions
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["states:*"],
                    resources=[
                        f"arn:aws:states:{RACC}:stateMachine:{self.afa_stack_name}*",
                    ],
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
                        "ecr:UntagResource",
                    ],
                    resources=["*"],
                ),
            ],
        )

        self.pipeline = self.make_codepipeline(codebuild_role)

        return

    def make_codepipeline(self, role):
        """Make the codepieline project that does the nested deployment of the
        AfaStack and AfaLambdaMapStack.

        """

        install_cmds = [
            "export CDK_TAGS=$(aws cloudformation describe-stacks --stack-name "
            f"{core.Aws.STACK_NAME} --query Stacks[0].Tags | "
            """python -c 'import sys, json; print(" ".join("--tags " + d["Key"] """
            """+ "=" + d["Value"] for d in json.load(sys.stdin)))')""",
            "export AWS_ACCOUNT_ID=$(aws sts get-caller-identity "
            "--query Account --output text)",
            "export BOOTSTRAP_URL=aws://$AWS_ACCOUNT_ID/$AWS_DEFAULT_REGION",
            "npm i --silent --quiet --no-progress -g aws-cdk@2.17.0",
            '(( [[ -n "CDK_TAGS" ]] ) && ( cdk bootstrap ${BOOTSTRAP_URL} )) || '
            "( cdk bootstrap ${BOOTSTRAP_URL} )",
        ]

        lambdamap_stack_cmds = [
            f"git clone {LAMBDAMAP_REPO_URL}",
            "cd lambdamap/",
            f"git checkout {self.lambdamap_branch.value_as_string}",
            'make deploy STACK_NAME=$LAMBDAMAP_STACK_NAME CDK_TAGS="$CDK_TAGS" '
            "FUNCTION_NAME=$LAMBDAMAP_FUNCTION_NAME "
            f"EXTRA_CMDS=\"'git clone {AFA_REPO_URL} ; "
            f"cd ./simple-forecast-solution/ ; "
            f"git checkout {self.afa_branch.value_as_string} ; "
            "pip install -q --use-deprecated=legacy-resolver -e .'\"",
        ]

        afa_stack_cmds = [
            f"git clone {AFA_REPO_URL}",
            "cd simple-forecast-solution/",
            f"git checkout {self.afa_branch.value_as_string}",
            "make deploy-ui EMAIL=$EMAIL INSTANCE_TYPE=$INSTANCE_TYPE "
            'AFA_STACK_NAME=$AFA_STACK_NAME CDK_TAGS="$CDK_TAGS" ',
        ]

        bucket = s3.Bucket.from_bucket_name(self, "BootstrapBucket", "afa-artifacts")
        source_artifact = codepipeline.Artifact("DummyArtifact")

        s3_action = codepipeline_actions.S3SourceAction(
            action_name="source",
            bucket=bucket,
            bucket_key="build.zip",
            output=source_artifact,
        )

        # environment variables for the codebuild actions
        env_variables = {
            "LAMBDAMAP_STACK_NAME": codebuild.BuildEnvironmentVariable(
                value=LAMBDAMAP_STACK_NAME
            ),
            "LAMBDAMAP_FUNCTION_NAME": codebuild.BuildEnvironmentVariable(
                value=self.lambdamap_function_name.value_as_string
            ),
            "EMAIL": codebuild.BuildEnvironmentVariable(
                value=self.email_address.value_as_string
            ),
            "INSTANCE_TYPE": codebuild.BuildEnvironmentVariable(
                value=self.instance_type.value_as_string
            ),
            "AFA_STACK_NAME": codebuild.BuildEnvironmentVariable(
                value=self.afa_stack_name
            ),
        }

        # codebuild action to deploy the AfaLambdaMapStack
        lambdamap_stack_action = codepipeline_actions.CodeBuildAction(
            action_name="DeployAfaLambdaMapStack",
            project=codebuild.PipelineProject(
                self,
                "LambdaMapStackProject",
                environment=codebuild.BuildEnvironment(
                    privileged=True,
                    build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2_4,
                ),
                environment_variables=env_variables,
                build_spec=codebuild.BuildSpec.from_object(
                    {
                        "version": "0.2",
                        "phases": {
                            "install": {
                                "runtime-versions": {"python": "3.9", "nodejs": "16"},
                                "commands": install_cmds,
                            },
                            "build": {"commands": lambdamap_stack_cmds},
                        },
                    }
                ),
                role=role,
            ),
            input=source_artifact,
        )

        # codebuild action to deploy the AfaStack
        afa_stack_action = codepipeline_actions.CodeBuildAction(
            action_name="DeployAfaStack",
            project=codebuild.PipelineProject(
                self,
                "AfaStackProject",
                environment=codebuild.BuildEnvironment(
                    privileged=True,
                    build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2_4,
                ),
                environment_variables=env_variables,
                build_spec=codebuild.BuildSpec.from_object(
                    {
                        "version": "0.2",
                        "phases": {
                            "install": {
                                "runtime-versions": {"python": "3.9", "nodejs": "16"},
                                "commands": install_cmds,
                            },
                            "build": {"commands": afa_stack_cmds},
                        },
                    }
                ),
                role=role,
            ),
            input=source_artifact,
        )

        # codepipeline to deploy all stacks
        pipeline = codepipeline.Pipeline(
            self,
            "BootstrapPipeline",
            stages=[
                codepipeline.StageProps(stage_name="Source", actions=[s3_action]),
                codepipeline.StageProps(
                    stage_name="Deploy",
                    actions=[lambdamap_stack_action, afa_stack_action],
                ),
            ],
        )

        return pipeline


if __name__ == "__main__":
    app = core.App()
    core.Tags.of(app).add(TAG_NAME, TAG_VALUE)
    stack = BootstrapStack(app, "AfaBootstrapStack")
    app.synth()
