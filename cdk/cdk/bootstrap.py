import os

from textwrap import dedent
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    core,
    core as cdk
)

PWD = os.path.dirname(os.path.realpath(__file__))


class BootstrapStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        email_address = core.CfnParameter(self, "emailAddress",
                allowed_pattern=".+",
                description="(Required) An e-mail address with which to receive "
                "deployment notifications.")

        #   instance_type = core.CfnParameter(self, "instanceType",
        #           default="ml.t2.medium",
        #           description="(Required) SageMaker Notebook instance type on which to host "
        #           "the AFA dashboard (e.g. ml.t2.medium, ml.t3.xlarge, ml.t3.2xlarge, ml.m4.4xlarge)")
        instance_type = "ml.t2.medium"

        vpc = ec2.Vpc(self, f"{construct_id}-Vpc", max_azs=1)

        ec2_role = iam.Role(
            self,
            "AfaInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("IAMFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy")
            ])

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:cloudformation:{self.region}:{self.account}:*"],
            actions=["cloudformation:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:logs:{self.region}:{self.account}:*"],
            actions=["logs:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[
                f"arn:aws:s3:::cdktoolkit-stagingbucket-*",
                f"arn:aws:s3:::*-{self.account}-{self.region}",
            ],
            actions=["s3:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:lambda:{self.region}:{self.account}:*"],
            actions=["lambda:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:ssm:{self.region}:{self.account}:*"],
            actions=["ssm:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:states:{self.region}:{self.account}:*"],
            actions=["states:*"]
        ))

        ec2_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:sns:{self.region}:{self.account}:*"],
            actions=["sns:*"]
        ))

        ami = ec2.MachineImage.generic_linux({
            "ap-southeast-2": "ami-0aab712d6363da7f9"
        })

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            dedent(f"""
            set -x -v -e

            # install git
            yum install -y git

            # install + start docker
            amazon-linux-extras install -y docker
            systemctl enable docker
            systemctl start docker
            usermod -aG docker ec2-user 
            setfacl --modify user:ec2-user:rw /var/run/docker.sock

            # install miniconda into ~/SageMaker/miniconda, which will make it
            # persistent
            CONDA_DIR=~/miniconda/

            mkdir -p "$CONDA_DIR"

            wget -q https://repo.anaconda.com/miniconda/Miniconda3-py39_4.10.3-Linux-x86_64.sh \
                -O "$CONDA_DIR/miniconda.sh"
            bash "$CONDA_DIR/miniconda.sh" -b -u -p "$CONDA_DIR"
            rm -rf "$CONDA_DIR/miniconda.sh"

            # use local miniconda distro
            source "$CONDA_DIR/bin/activate"

            # install custom conda environment(s)
            conda create -y -q -n py39 python=3.9 nodejs=14
            conda activate py39

            # install the aws-cdk cli tool (req. for running `cdk deploy ...`)
            npm i -g aws-cdk@1.116.0 &>/dev/null

            # deploy the AfaLambdaMapStack (required by the dashboard code)
            git clone https://github.com/aws-samples/lambdamap.git
            cd ./lambdamap/lambdamap_cdk/
            pip install -r ./requirements.txt
            cdk bootstrap aws://{self.account}/{self.region} &>/dev/null
            nohup cdk deploy --require-approval never \
                --context stack_name=AfaLambdaMapStack \
                --context function_name=AfaLambdaMapFunction \
                --context memory_size=256 \
                --context extra_cmds='git clone https://github.com/aws-samples/simple-forecast-solution.git ; cd ./simple-forecast-solution/ ; git checkout main ; pip install -e .' &

            git clone https://github.com/aws-samples/simple-forecast-solution.git
            cd ./simple-forecast-solution
            git checkout main
            cd ./cdk
            pip install -r ./requirements.txt
            cdk bootstrap aws://{self.account}/{self.region} &>/dev/null
            nohup cdk deploy AfaStack \
                --parameters AfaStack:emailAddress={email_address.value_as_string} \
                --parameters AfaStack:instanceType={instance_type} \
                --require-approval never &
            """)
        )

        instance = ec2.Instance(
            self,
            f"{construct_id}-Instance",
            instance_name=f"{construct_id}-Instance",
            instance_type=ec2.InstanceType("t2.micro"),
            block_devices=[{
                "deviceName": "/dev/xvda",
                "volume": ec2.BlockDeviceVolume.ebs(
                    volume_size=8,
                    delete_on_termination=True)
            }],
            machine_image=ami,
            user_data=user_data,
            role=ec2_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC))
