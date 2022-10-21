#!/usr/bin/env python3
from textwrap import dedent

import aws_cdk as core
from aws_cdk import Aws, Stack
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

AFA_REPO_URL = "https://github.com/aws-samples/simple-forecast-solution.git"
LAMBDAMAP_REPO_URL = "https://github.com/aws-samples/lambdamap.git"

LAMBDAMAP_STACK_NAME = "AfaLambdaMapStack"
LAMBDAMAP_FUNCTION_NAME = "AfaLambdaMapFunction"

TAG_NAME = "Project"
TAG_VALUE = "Afa"
RACC = f"{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}"
ACCOUNT_ID = Aws.ACCOUNT_ID

# The lambda function to start a build of the codebuild project


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

        # Add any policies needed to deploy the main stack
        self.codebuild_role = iam.Role(
            self,
            "AfaCodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonEC2ContainerRegistryPowerUser"
                )
            ],
        )

        # lambdamap codebuild policy
        lambdamap_policy = iam.Policy(
            self,
            "LambdaMapCodeBuildPolicy",
            roles=[self.codebuild_role],
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "cloudformation:CreateChangeSet",
                        "cloudformation:CreateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:DescribeChangeSet",
                        "cloudformation:ListChangeSets",
                        "cloudformation:ListStackResources",
                        "cloudformation:TagResources",
                        "cloudformation:UpdateStack",
                        "cloudformation:GetTemplate",
                        "cloudformation:ExecuteChangeSet",
                        "cloudformation:DeleteChangeSet",
                    ],
                    resources=[
                        f"arn:aws:cloudformation:{RACC}:stack/{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:cloudformation:{RACC}:stack/{Aws.STACK_NAME}/*",
                        f"arn:aws:cloudformation:{RACC}:stack/CDKToolkit/*",
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
                        f"arn:aws:iam::{ACCOUNT_ID}:role/{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:iam::{ACCOUNT_ID}:policy/{LAMBDAMAP_STACK_NAME}*",
                        f"arn:aws:iam::{ACCOUNT_ID}:role/cdk-*",
                        f"arn:aws:lambda:*:{ACCOUNT_ID}:policy/{LAMBDAMAP_STACK_NAME}*",
                    ],
                ),
                # CodeBuild logs
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogStream",
                    ],
                    resources=[f"arn:aws:logs:{RACC}:log-group:/aws/codebuild/"],
                ),
                # Lambda
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:CreateFunction",
                        "lambda:GetFunction",
                        "lambda:ListTags",
                        "lambda:UpdateFunctionCode",
                        "lambda:TagResource",
                    ],
                    resources=[
                        f"arn:aws:lambda:{RACC}:function:"
                        f"{self.lambdamap_function_name.value_as_string}",
                    ],
                ),
                # S3
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:CreateBucket",
                        "s3:GetObject*",
                        "s3:GetBucketPolicy*",
                        "s3:PutObject*",
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetEncryptionConfiguration",
                        "s3:PutEncryptionConfiguration",
                        "s3:PutBucketVersioning",
                        "s3:SetBucketEncryption",
                        "s3:PutAccountPublicAccessBlock",
                        "s3:PutBucketLogging",
                        "s3:PutBucketPublicAccessBlock",
                        "s3:PutBucketTagging",
                        "s3:PutBucketVersioning",
                        "s3:PutBucketPolicy",
                        "s3:PutObjectTagging",
                        "s3:DeleteBucketPolicy",
                    ],
                    resources=["arn:aws:s3:::cdk-*", "arn:aws:s3:::cdktoolkit-*"],
                ),
                # ECR
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
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
                        "ecr:PutImageScanningConfiguration",
                        "ecr:PutImageTagMutability",
                        "ecr:DeleteRepository",
                        "ecr:TagResource",
                        "ecr:UntagResource",
                    ],
                    resources=[
                        f"arn:aws:ecr:{RACC}:repository/cdk-*-"
                        f"{ACCOUNT_ID}-{Aws.REGION}",
                        f"arn:aws:ecr:{RACC}:repository/aws-cdk/assets",
                    ],
                ),
                # ECR
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ecr:GetAuthorizationToken",
                        "ecr:CreateRepository",
                    ],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # STS
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # EC2
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ec2:DescribeAvailabilityZones",
                    ],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # SSM
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "ssm:PutParameter",
                        "ssm:DeleteParameter",
                        "ssm:ListTagsForResource",
                        "ssm:AddTagsToResource",
                        "ssm:RemoveTagsFromResource",
                        "ssm:UntagResource",
                    ],
                    resources=[f"arn:aws:ssm:{RACC}:parameter/cdk-bootstrap/*"],
                ),
            ],
        )

        lambdamap_policy.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {"id": "W12", "reason": "These actions require '*' resources."},
                ]
            }
        }

        # afa codebuild policy
        afa_policy = iam.Policy(
            self,
            "AfaCodeBuildPolicy",
            roles=[self.codebuild_role],
            statements=[
                #
                # CloudFormation
                #
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "cloudformation:CreateChangeSet",
                        "cloudformation:CreateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:DescribeChangeSet",
                        "cloudformation:ListChangeSets",
                        "cloudformation:ListStackResources",
                        "cloudformation:TagResources",
                        "cloudformation:UpdateStack",
                        "cloudformation:GetTemplate",
                        "cloudformation:ExecuteChangeSet",
                        "cloudformation:DeleteChangeSet",
                    ],
                    resources=[
                        f"arn:aws:cloudformation:{RACC}:stack/{self.afa_stack_name}*",
                        f"arn:aws:cloudformation:{RACC}:stack/{Aws.STACK_NAME}/*",
                        f"arn:aws:cloudformation:{RACC}:stack/CDKToolkit/*",
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
                        f"arn:aws:iam::{ACCOUNT_ID}:role/{self.afa_stack_name}*",
                        f"arn:aws:iam::{ACCOUNT_ID}:role/cdk-*-"
                        f"{ACCOUNT_ID}-{Aws.REGION}",
                        f"arn:aws:iam::{ACCOUNT_ID}:policy/{self.afa_stack_name}*",
                        f"arn:aws:lambda:*:{ACCOUNT_ID}:policy/{self.afa_stack_name}*",
                    ],
                ),
                # CodeBuild logs
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogStream",
                    ],
                    resources=[f"arn:aws:logs:{RACC}:log-group:/aws/codebuild/"],
                ),
                # Lambda
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:CreateFunction",
                        "lambda:GetFunction",
                        "lambda:ListTags",
                        "lambda:UpdateFunctionCode",
                        "lambda:TagResource",
                    ],
                    resources=[
                        f"arn:aws:lambda:{RACC}:function:{self.afa_stack_name}*"
                    ],
                ),
                # S3
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:CreateBucket",
                        "s3:GetObject*",
                        "s3:PutObject*",
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                    ],
                    resources=["arn:aws:s3:::cdk-*", "arn:aws:s3:::cdktoolkit-*"],
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
                    actions=[
                        "sns:CreateTopic",
                        "sns:GetTopicAttributes",
                        "sns:ListTagsForResource",
                        "sns:TagResource",
                    ],
                    resources=[
                        f"arn:aws:sns:{RACC}:{self.afa_stack_name}-NotificationTopic"
                    ],
                ),
                # SSM
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "ssm:PutParameter",
                        "ssm:ListTagsForResource",
                        "ssm:AddTagsToResource",
                        "ssm:RemoveTagsFromResource",
                        "ssm:UntagResource",
                        "ssm:DeleteParameter",
                    ],
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
                    actions=[
                        "states:CreateStateMachine",
                        "states:DeleteStateMachine",
                        "states:DescribeStateMachine",
                        "states:ListTagsForResource",
                        "states:TagResource",
                        "states:UntagResource",
                    ],
                    resources=[
                        f"arn:aws:states:{RACC}:stateMachine:{self.afa_stack_name}*",
                    ],
                ),
                # ECR
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
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
                        "ecr:PutImageScanningConfiguration",
                        "ecr:PutImageTagMutability",
                        "ecr:DeleteRepository",
                        "ecr:TagResource",
                        "ecr:UntagResource",
                    ],
                    resources=[
                        f"arn:aws:ecr:{RACC}:repository/cdk-*-"
                        f"{ACCOUNT_ID}-{Aws.REGION}",
                        f"arn:aws:ecr:{RACC}:repository/aws-cdk/assets",
                    ],
                ),
                # STS
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                # EC2
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ec2:DescribeAvailabilityZones",
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

        afa_policy.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {"id": "W12", "reason": "These actions require '*' resources."},
                ]
            }
        }

        self.make_codebuild_project(self.codebuild_role)
        self.deploy_stacks()

        return

    def make_codebuild_project(self, codebuild_role):
        """Make the codepieline project that does the nested deployment of the
        AfaStack and AfaLambdaMapStack.

        """

        install_cmds = [
            "export CDK_TAGS=$(aws cloudformation describe-stacks --stack-name="
            f"{core.Aws.STACK_NAME} --query Stacks[0].Tags | "
            """python -c 'import sys, json; print(" ".join("--tags " + d["Key"] """
            """+ "=" + d["Value"] for d in json.load(sys.stdin)))')""",
            "export AWS_ACCOUNT_ID=$(aws sts get-caller-identity "
            "--query Account --output text)",
            "export BOOTSTRAP_URL=aws://$AWS_ACCOUNT_ID/$AWS_DEFAULT_REGION",
            "npm i --silent --quiet --no-progress -g aws-cdk@2.45.0",
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
            "cd ..",
            f"git clone {AFA_REPO_URL}",
            "cd simple-forecast-solution/",
            f"git checkout {self.afa_branch.value_as_string}",
            "pip install -q -r ./requirements.txt",
            "make deploy-ui "
            "   EMAIL=$EMAIL INSTANCE_TYPE=$INSTANCE_TYPE"
            "   AFA_BRANCH=$AFA_BRANCH LAMBDAMAP_BRANCH=$LAMBDAMAP_BRANCH"
            '   AFA_STACK_NAME=$AFA_STACK_NAME CDK_TAGS="$CDK_TAGS"',
        ]

        # environment variables for the codebuild actions
        env_variables = {
            "LAMBDAMAP_BRANCH": codebuild.BuildEnvironmentVariable(
                value=self.lambdamap_branch.value_as_string
            ),
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
            "AFA_BRANCH": codebuild.BuildEnvironmentVariable(
                value=self.afa_branch.value_as_string
            ),
        }

        # codebuild project to deploy the AfaLambdaMapStack
        self.deploy_stacks_project = codebuild.Project(
            self,
            "DeployStacksProject",
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
                        "build": {"commands": lambdamap_stack_cmds + afa_stack_cmds},
                    },
                }
            ),
            role=codebuild_role,
        )

        return

    def deploy_stacks(self):
        """ """

        inline_lambda_str = dedent(
            """
        import os
        import json
        import boto3
        import cfnresponse

        def lambda_handler(event, context):
            client = boto3.client("codebuild")
            client.start_build(projectName=os.environ["PROJECT_NAME"])
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {},
                "CustomResourcePhysicalID")
            return
        """
        )

        lambda_role = iam.Role(
            self,
            "LambdaRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lambda.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )

        lambda_policy = iam.Policy(
            self,
            "LambdaPolicy",
            roles=[lambda_role],
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["codebuild:StartBuild"],
                    resources=[
                        self.deploy_stacks_project.project_arn,
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["codebuild:ListProjects"],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:ResourceAccount": Aws.ACCOUNT_ID,
                            "aws:SourceAccount": Aws.ACCOUNT_ID,
                        }
                    },
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lambda:GetFunction",
                        "lambda:ListTags",
                        "lambda:TagResource",
                        "lambda:InvokeFunction",
                    ],
                    resources=[f"arn:aws:lambda:{RACC}:function:DeployStacksFunction"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=[
                        f"arn:aws:logs:{RACC}:log-group:/aws/lambda/",
                        f"arn:aws:logs:{RACC}:log-group:/aws/lambda/{Aws.STACK_NAME}*",
                    ],
                ),
            ],
        )

        lambda_policy.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {"id": "W12", "reason": "These actions require '*' resources."}
                ]
            }
        }

        deploy_func = lambda_.Function(
            self,
            "DeployStacksFunction",
            runtime=lambda_.Runtime.PYTHON_3_9,
            code=lambda_.Code.from_inline(inline_lambda_str),
            handler="index.lambda_handler",
            environment={
                "PROJECT_NAME": self.deploy_stacks_project.project_name,
            },
            role=lambda_role,
        )

        deploy_func.node.default_child.cfn_options.metadata = {
            "cfn_nag": {
                "rules_to_suppress": [
                    {
                        "id": "W89",
                        "reason": "Function does not access resources in a VPC.",
                    },
                    {
                        "id": "W92",
                        "reason": "Function only runs once during CFN deploys.",
                    },
                    {
                        "id": "W58",
                        "reason": "Function has permissions to write to CW logs.",
                    },
                ]
            }
        }

        cust_resource = core.CustomResource(
            self, "CustomResource", service_token=deploy_func.function_arn
        )

        cust_resource.node.add_dependency(self.deploy_stacks_project)

        return


if __name__ == "__main__":
    app = core.App()
    core.Tags.of(app).add(TAG_NAME, TAG_VALUE)
    stack = BootstrapStack(app, "AfaBootstrapStack")
    app.synth()
