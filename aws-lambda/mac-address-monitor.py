import json
import os

import boto3


def handler(event, context):
    print(event)
    # print(context)

    msg = 'Elvis has left the building'

    if 'present' in event['path']:
        msg = 'Elvis has arrived'

    client = boto3.client('sns')

    response = client.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Message=msg,
    )

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception

    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS'
        },
        'body': json.dumps('Signalled!')
    }
