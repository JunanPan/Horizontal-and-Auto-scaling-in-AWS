
import boto3
import botocore
import os
import requests
import time
import json
import configparser
import re
import datetime
import pytz
from dateutil.parser import parse

script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, 'horizontal-scaling-config.json')


########################################
# Constants
########################################
with open('horizontal-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
VPC_ID = configuration['vpc_id']

# Credentials fetched from environment variables
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
    instance = None
    # TODO: Create an EC2 instance
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

    # Reload the instance attributes
    instance.load()


    return instance


def initialize_test(lg_dns, first_web_service_dns):
    """
    Start the horizontal scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/test/horizontal?dns={}'.format(
        lg_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    # TODO: return log File name
    log_file_name = get_test_id(response)

    return log_file_name


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


def is_test_complete(lg_dns, log_name):
    """
    Check if the horizontal scaling test has finished
    :param lg_dns: load generator DNS
    :param log_name: name of the log file
    :return: True if Horizontal Scaling test is complete and False otherwise.
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    log_text = requests.get(log_string).text
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


def add_web_service_instance(lg_dns, sg2_id, log_name):
    """
    Launch a new WS (Web Server) instance and add to the test
    :param lg_dns: load generator DNS
    :param sg2_id: id of WS security group
    :param log_name: name of the log file
    """
    ins = create_instance(WEB_SERVICE_AMI, sg2_id)
    print("New WS launched. id={}, dns={}".format(
        ins.instance_id,
        ins.public_dns_name)
    )
    add_req = 'http://{}/test/horizontal/add?dns={}'.format(
        lg_dns,
        ins.public_dns_name
    )
    while True:
        if requests.get(add_req).status_code == 200:
            print("New WS submitted to LG.")
            break
        elif is_test_complete(lg_dns, log_name):
            print("New WS not submitted because test already completed.")
            break


def authenticate(lg_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param lg_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """

    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        lg_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass


def get_rps(lg_dns, log_name):
    """
    Return the current RPS as a floating point number
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: latest RPS value
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    config = configparser.ConfigParser(strict=False)
    config.read_string(requests.get(log_string).text)
    sections = config.sections()
    sections.reverse()
    rps = 0
    for sec in sections:
        if 'Current rps=' in sec:
            rps = float(sec[len('Current rps='):])
            break
    return rps


def get_test_start_time(lg_dns, log_name):
    """
    Return the test start time in UTC
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: datetime object of the start time in UTC
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    start_time = None
    while start_time is None:
        config = configparser.ConfigParser(strict=False)
        config.read_string(requests.get(log_string).text)
        # By default, options names in a section are converted
        # to lower case by configparser
        start_time = dict(config.items('Test')).get('starttime', None)
    return parse(start_time)


def find_security_group_by_name(group_name):
    security_groups = list(ec2.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': [group_name]}]))
    if security_groups:
        return security_groups[0]
    else:
        return None

########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Provision resources to achieve horizontal scalability
    #   - Create security groups for Load Generator and Web Service
    #   - Provision a Load Generator instance
    #   - Provision a Web Service instance
    #   - Register Web Service DNS with Load Generator
    #   - Add Web Service instances to Load Generator
    #   - Terminate resources

    print_section('1 - create two security groups')
    sg_permissions = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # TODO: Create two separate security groups and obtain the group ids
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')
    sg1 = find_security_group_by_name('LoadGeneratorSecurityGroup')
    if not sg1:
        sg1 = ec2.create_security_group( # Security group for Load Generator instances
            Description='Security group for Load Generator instances',
            GroupName='LoadGeneratorSecurityGroup',
            VpcId = VPC_ID
        )
    sg1.authorize_ingress(IpPermissions=sg_permissions)
    sg1_id = sg1.id

    sg2 = find_security_group_by_name('WebServiceSecurityGroup')
    if not sg2:
        sg2 = ec2.create_security_group( # Security group for Web Service instances
            Description = 'Security group for Web Service instances',
            GroupName = 'WebServiceSecurityGroup',
            VpcId = VPC_ID
        )
    sg2.authorize_ingress(IpPermissions=sg_permissions)
    sg2_id = sg2.id

    print_section('2 - create LG')

    # TODO: Create Load Generator instance and obtain ID and DNS
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    lg_id = lg.instance_id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    # TODO: Create First Web Service Instance and obtain the DNS

    web_service_instance = create_instance(WEB_SERVICE_AMI, sg2_id)
    web_service_dns = web_service_instance.public_dns_name

    print_section('4. Submit the first WS instance DNS to LG, starting test.')
    log_name = initialize_test(lg_dns, web_service_dns)
    last_launch_time = get_test_start_time(lg_dns, log_name)
    while not is_test_complete(lg_dns, log_name):
        # TODO: Check RPS and last launch time
        # TODO: Add New Web Service Instance if Required
        if get_rps(lg_dns, log_name) < 50:
            last_launch_time = get_test_start_time(lg_dns, log_name)
            #get current time, I mean current, now now!!
            current_time = datetime.datetime.now(pytz.utc)
            if current_time - last_launch_time > datetime.timedelta(seconds=100):
                add_web_service_instance(lg_dns, sg2_id, log_name)
                last_launch_time = current_time


        time.sleep(1)

    print_section('End Test')

    # TODO: Terminate Resources
    boto3.setup_default_session(region_name='us-east-1')
    ec2 = boto3.resource('ec2')
    ec2.instances.filter(InstanceIds=[lg_id]).terminate()
    ec2.instances.filter(InstanceIds=[web_service_instance.instance_id]).terminate()
    ec2.security_groups.filter(GroupIds=[sg1_id]).delete()
    ec2.security_groups.filter(GroupIds=[sg2_id]).delete()



if __name__ == '__main__':
    main()
