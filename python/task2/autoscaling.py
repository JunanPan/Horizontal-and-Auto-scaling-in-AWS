
import boto3
import botocore
import os
import requests
import time
import json
import re

########################################
# Constants
########################################
with open('auto-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
VPC_ID = configuration['vpc_id']

SUBMISSION_USERNAME = os.environ['SUBMISSION_USERNAME']
SUBMISSION_PASSWORD = os.environ['SUBMISSION_PASSWORD']

########################################
# Tags
########################################
tag_pairs = [
    ("Project", "vm-scaling"),
]
TAGS = [{'Key': k, 'Value': v} for k, v in tag_pairs]

TEST_NAME_REGEX = r'name=(.*log)'

########################################
# Utility functions
########################################


def create_instance(ami, sg_id):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_id: ID of the security group to be attached to instance
    :return: instance object
    """
    # Create an EC2 instance
    instance = None
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')
    instance = ec2.create_instances(
        ImageId=ami,
        MinCount=1,
        MaxCount=1,
        InstanceType=INSTANCE_TYPE,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': TAGS
            }
        ]
    )[0]
    # Wait for the instance to enter the running state
    instance.wait_until_running()

    return instance


def initialize_test(load_generator_dns, first_web_service_dns):
    """
    Start the auto scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/autoscaling?dns={}'.format(
        load_generator_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    # return log File name
    log_file_name = get_test_id(response)
    return log_file_name


def initialize_warmup(load_generator_dns, load_balancer_dns):
    """
    Start the warmup test
    :param lg_dns: Load Generator DNS
    :param load_balancer_dns: Load Balancer DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/warmup?dns={}'.format(
        load_generator_dns, load_balancer_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass  

    # return log File name
    log_file_name = get_test_id(response)
    return log_file_name


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


def destroy_resources(sg1, sg2, lg, lt, tg, lb, asg, scale_up_policy_arn, scale_down_policy_arn, cloudwatch):
    """
    Delete all resources created for this task

    You must destroy the following resources:
    Load Generator, Auto Scaling Group, Launch Template, Load Balancer, Security Group.
    Note that one resource may depend on another, and if resource A depends on resource B, you must delete resource B before you can delete resource A.
    Below are all the resource dependencies that you need to consider in order to decide the correct ordering of resource deletion.

    - You cannot delete Launch Template before deleting the Auto Scaling Group
    - You cannot delete a Security group before deleting the Load Generator and the Auto Scaling Groups
    - You must wait for the instances in your target group to be terminated before deleting the security groups

    :param msg: message
    :return: None
    """
    # TODO: implement this method
    # delete all resources
    # delete the ASG
    asg.delete_auto_scaling_group(
        AutoScalingGroupName='WebServerASG'
    )
    # delete the launch template
    lt.delete_launch_template(
        LaunchTemplateName='WebServerTemplate'
    )
    # delete the load balancer
    elbv2.delete_load_balancer(
        LoadBalancerArn=lb_arn
    )
    # delete the target group
    elbv2.delete_target_group(
        TargetGroupArn=tg_arn
    )
    # delete the security groups
    sg1.delete()
    sg2.delete()
    # delete the load generator
    lg.terminate()
    # delete the scaling policies
    asg.delete_policy(
        PolicyName='ScaleUp'
    )
    asg.delete_policy(
        PolicyName='ScaleDown'
    )
    # delete the cloudwatch alarms
    cloudwatch.delete_alarms(
        AlarmNames=[
            'ScaleUp',
            'ScaleDown'
        ]
    )



    pass


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(load_generator_dns, log_name):
    """
    Check if auto scaling test is complete
    :param load_generator_dns: lg dns
    :param log_name: log file name
    :return: True if Auto Scaling test is complete and False otherwise.
    """
    log_string = 'http://{}/log?name={}'.format(load_generator_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    log_text = requests.get(log_string).text
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


def authenticate(load_generator_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param load_generator_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """
    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        load_generator_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass

        
def find_security_group_by_name(ec2, group_name):
    security_groups = list(ec2.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': [group_name]}]))
    if security_groups:
        return security_groups[0]
    else:
        return None

########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Programmatically provision autoscaling resources
    #   - Create security groups for Load Generator and ASG, ELB
    #   - Provision a Load Generator
    #   - Generate a Launch Template
    #   - Create a Target Group
    #   - Provision a Load Balancer
    #   - Associate Target Group with Load Balancer
    #   - Create an Autoscaling Group
    #   - Initialize Warmup Test
    #   - Initialize Autoscaling Test
    #   - Terminate Resources

    print_section('1 - create two security groups')

    PERMISSIONS = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # create two separate security groups and obtain the group ids
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')

    # Security group for Load Generator instances
    sg1 = find_security_group_by_name(ec2,'LoadGeneratorSecurityGroup')
    if not sg1:
        sg1 = ec2.create_security_group( 
            Description='Security group for Load Generator instances',
            GroupName='LoadGeneratorSecurityGroup',
            VpcId = VPC_ID
        )
        sg1.authorize_ingress(IpPermissions=sg_permissions)
    sg1_id = sg1.id

    # Security group for ASG, ELB instances
    sg2 = find_security_group_by_name(ec2,"ASG_ELBSecurityGroup")
    if not sg2:
        sg2 = ec2.create_security_group(
            Description = 'Security group for ASG, ELB instances',
            GroupName = 'ASG_ELBSecurityGroup',
            VpcId = VPC_ID
        )
        sg2.authorize_ingress(IpPermissions=sg_permissions)
    sg2_id = sg2.id

    print_section('2 - create LG')

    # Create Load Generator instance and obtain ID and DNS
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    lg_id = lg.id
    lg_dns = lg.public_dns_name

    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Create LT (Launch Template)')
    # create launch Template
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.client('ec2')
    lt = ec2.create_launch_template(
        LaunchTemplateName='WebServerTemplate',
        LaunchTemplateData={
            'ImageId': WEB_SERVICE_AMI,
            'InstanceType': INSTANCE_TYPE,
            'SecurityGroupIds': [sg2_id],
            'TagSpecifications': [
                {
                    'ResourceType': 'instance',
                    'Tags': TAGS
                }
            ]
        }
    )
    print_section('4. Create TG (Target Group)')
    # TODO: create Target Group
    boto3.setup_default_session(region_name='us-east-1')
    elbv2 = boto3.client('elbv2')
    tg = elbv2.create_target_group(
        Name='WebServerTargetGroup',
        Protocol='HTTP',
        Port=80,
        VpcId=VPC_ID,
        HealthCheckProtocol='HTTP',
        HealthCheckPort='80',
        HealthCheckPath='/',
        HealthCheckIntervalSeconds=50,
        HealthCheckTimeoutSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        TargetType='instance'
    )
    tg_arn = tg['TargetGroups'][0]['TargetGroupArn']


    print_section('5. Create ELB (Elastic/Application Load Balancer)')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    boto3.setup_default_session(region_name='us-east-1')
    elbv2 = boto3.client('elbv2')
    lb = elbv2.create_load_balancer(
        Name='WebServerLoadBalancer',
        Subnets=[
            'subnet-0a704a99fa14a64c4',
            'subnet-00bc4aa1925ecc48a'
        ],
        SecurityGroups=[
            sg2_id
        ],
        Scheme='internet-facing',
        Tags=TAGS
    )

    lb_arn = lb['LoadBalancers'][0]['LoadBalancerArn']
    lb_dns = lb['LoadBalancers'][0]['DNSName']

    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))

    print_section('6. Associate ELB with target group')
    # TODO Associate ELB with target group
    boto3.setup_default_session(region_name='us-east-1')
    elbv2 = boto3.client('elbv2')
    elbv2.register_targets(
        TargetGroupArn=tg_arn,
        Targets=[
            {
                'Id': lg_id
            }
        ]
    )

    print_section('7. Create ASG (Auto Scaling Group)')
    # TODO create Autoscaling group
    boto3.setup_default_session(region_name='us-east-1')
    asg = boto3.client('autoscaling')
    asg.create_auto_scaling_group(
        AutoScalingGroupName='WebServerASG',
        LaunchTemplate={
            'LaunchTemplateName': 'WebServerTemplate',
            'Version': '$Latest'
        },
        MinSize=1,
        MaxSize=5,
        DesiredCapacity=2,
        VPCZoneIdentifier='subnet-0a704a99fa14a64c4,subnet-00bc4aa1925ecc48a',
        TargetGroupARNs=[
            tg_arn
        ],
        Tags=TAGS
    )

    print_section('8. Create policy and attached to ASG')
    # TODO Create Simple Scaling Policies for ASG
    asg.put_scaling_policy(
        AutoScalingGroupName='WebServerASG',
        PolicyName='ScaleUp',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=1,
        Cooldown=100
    )
    scale_up_policy_arn = asg.describe_policies(
        AutoScalingGroupName='WebServerASG',
        PolicyNames=[
            'ScaleUp'
        ]
    )['ScalingPolicies'][0]['PolicyARN']

    asg.put_scaling_policy(
        AutoScalingGroupName='WebServerASG',
        PolicyName='ScaleDown',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=-1,
        Cooldown=100
    )
    scale_down_policy_arn = asg.describe_policies(
        AutoScalingGroupName='WebServerASG',
        PolicyNames=[
            'ScaleDown'
        ]
    )['ScalingPolicies'][0]['PolicyARN']

    print_section('9. Create Cloud Watch alarm. Action is to invoke policy.')
    # TODO create CloudWatch Alarms and link Alarms to scaling policies
    cloudwatch = boto3.client('cloudwatch')
    cloudwatch.put_metric_alarm(
        AlarmName='ScaleUp',
        ComparisonOperator='GreaterThanThreshold',
        EvaluationPeriods=1,
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Period=60,
        Statistic='Average',
        Threshold=90.0,
        ActionsEnabled=True,
        AlarmActions=[scale_up_policy_arn],
        AlarmDescription='Alarm when server CPU exceeds 90%',
        Dimensions=[
            {
                'Name': 'AutoScalingGroupName',
                'Value': 'WebServerASG'
            },
        ],
    )
    cloudwatch.put_metric_alarm(
        AlarmName='ScaleDown',
        ComparisonOperator='LessThanThreshold',
        EvaluationPeriods=1,
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Period=60,
        Statistic='Average',
        Threshold=10.0,
        ActionsEnabled=True,
        AlarmActions=[scale_down_policy_arn],
        AlarmDescription='Alarm when server CPU is less than 10%',
        Dimensions=[
            {
                'Name': 'AutoScalingGroupName',
                'Value': 'WebServerASG'
            },
        ],
    )

    print_section('10. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    print_section('11. Submit ELB DNS to LG, starting warm up test.')
    warmup_log_name = initialize_warmup(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, warmup_log_name):
        time.sleep(1)

    print_section('12. Submit ELB DNS to LG, starting auto scaling test.')
    # May take a few minutes to start actual test after warm up test finishes
    log_name = initialize_test(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)

    destroy_resources()


if __name__ == "__main__":
    main()
