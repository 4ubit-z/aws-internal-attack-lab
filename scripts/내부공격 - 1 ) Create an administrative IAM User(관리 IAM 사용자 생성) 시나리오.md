# AWS 내부공격 시나리오 - 관리 IAM 사용자 생성
<!--StartFragment--><html><head></head><body><h1>AWS 내부 공격 시나리오 -<br> Backdoor an S3 Bucket via Bucket Policy 실습 보고서</h1>

## 목차

1. [[실습 개요]](#실습-개요)
2. [[공격 시나리오]](#공격-시나리오)
3. [[탐지 및 방어 방안]](#탐지-및-방어-방안)
4. [[예방 및 완화 방안]](#예방-및-완화-방안)
5. [[대응 절차]](#대응-절차)
6. [[결론]](#결론)

## 실습 개요

### 실습 목적
AWS 환경에서 제한된 IAM 권한을 보유한 내부 사용자 또는 공격자가 IAM 사용자 생성 권한을 악용하여 관리자 권한을 가진 새로운 계정을 생성하고, 이를 통해 AWS 계정 전체에 대한 완전한 제어권을 획득하는 권한 상승(Privilege Escalation) 공격을 시뮬레이션한다.

### 실습 범위
- 제한된 IAM 권한으로 시작하는 공격 시나리오
- IAM 사용자 생성 및 관리자 권한 부여 과정
- 액세스 키 생성을 통한 백도어 계정 구축
- GuardDuty를 활용한 권한 상승 탐지
- Lambda와 SNS를 이용한 실시간 보안 알림 시스템 구축

### 사전 지식
- **IAM 권한 상승이란?** AWS IAM에서 권한 상승(Privilege Escalation)은 현재 보유한 제한된 권한을 이용하여 더 높은 수준의 권한을 획득하는 공격 기법입니다. 이는 정상적인 IAM 정책과 기능을 악용하여 수행되며, 탐지가 어려운 특징이 있습니다.
- **필요 최소 권한의 위험성** `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreateAccessKey` 권한은 개별적으로는 무해해 보이지만, 조합될 경우 강력한 공격 벡터가 될 수 있습니다.
- **실습 배경** 이 실습은 내부 직원이나 침투 테스터, 또는 초기 침해를 통해 제한된 AWS 접근 권한을 획득한 공격자가 어떻게 권한을 확대할 수 있는지를 보여주는 현실적인 시나리오를 다룹니다.

---

## 공격 시나리오

### 전제 조건

공격자는 다음과 같은 상황에서 공격을 수행할 수 있습니다:

- **초기 접근 권한 확보**: 탈취된 액세스 키, EC2 인스턴스 내 임시 크레덴셜, 내부자 접근 등
- **필요 최소 권한**:
  - `iam:CreateUser`
  - `iam:AttachUserPolicy`
  - `iam:CreateAccessKey`

### 공격 단계

#### 1단계: 새로운 IAM 사용자 생성

```bash
aws iam create-user --user-name attacker-admin
```

**공격자 의도:**
- 일반적인 사용자명을 사용하여 탐지를 회피
- 정상적인 운영 활동으로 위장
- 예시: `backup-service`, `monitoring-user`, `support-admin` 등

#### 2단계: 관리자 권한 정책 연결

```bash
aws iam attach-user-policy --user-name attacker-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**결과:**
- 생성된 사용자가 AWS 계정 내 모든 리소스에 대한 완전한 제어 권한 획득
- 권한 상승(Privilege Escalation) 완료

#### 3단계: 프로그래밍 접근을 위한 액세스 키 발급

```bash
aws iam create-access-key --user-name attacker-admin
```

**활용 방안:**
- AWS CLI, SDK, Terraform 등을 통한 지속적 접근
- 백도어 계정으로 활용
- 추가 공격 인프라 구축

### 공격 후 가능한 악의적 행위

1. **데이터 유출**: S3 버킷, RDS 데이터베이스 접근
2. **리소스 생성**: 암호화폐 채굴용 EC2 인스턴스 생성
3. **추가 계정 생성**: 공격 지속성 확보
4. **로그 삭제**: CloudTrail 로그 삭제로 흔적 제거
5. **네트워크 변경**: 보안 그룹, VPC 설정 변경

---

## 탐지 및 방어 방안

### AWS GuardDuty를 활용한 실시간 탐지

GuardDuty는 다음과 같은 권한 상승 시도를 자동으로 탐지합니다:

- `PrivilegeEscalation:IAMUser/AdministrativePermissions`
- `PrivilegeEscalation:IAMUser/PermissionPolicy`
- `PrivilegeEscalation:IAMUser/UpdateAssumeRolePolicy`

### Lambda 기반 자동 알림 시스템

#### 목적
GuardDuty 탐지 이벤트를 실시간으로 수신하여 보안 팀에게 즉시 알림을 전송하는 시스템입니다.

#### 주요 기능
- GuardDuty 이벤트 실시간 모니터링
- 이벤트 상세 정보 파싱 및 분석
- SNS를 통한 자동 경고 알림 발송
- 보안 팀의 신속한 대응 지원

#### Lambda 함수 코드

```python
import json
import boto3
import datetime

def lambda_handler(event, context):
    sns = boto3.client('sns')
    
    # GuardDuty 이벤트 상세 정보 파싱
    detail = event.get('detail', {})
    title = detail.get('title', '알 수 없음')
    type_name = detail.get('type', '알 수 없음')
    region = detail.get('region', '알 수 없음')
    severity = detail.get('severity', '알 수 없음')
    account_id = detail.get('accountId', '알 수 없음')
    resource = detail.get('resource', {}).get('resourceType', '알 수 없음')
    
    # 추가 정보 추출
    service = detail.get('service', {})
    event_first_seen = service.get('eventFirstSeen', '알 수 없음')
    event_last_seen = service.get('eventLastSeen', '알 수 없음')
    
    # 현재 시간
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S KST')
    
    # SNS 메시지 생성
    subject = "경고: GuardDuty 권한 상승 시도 탐지됨"
    message = (
        f"GuardDuty 탐지 이벤트: 권한 상승 위험\n\n"
        f"이벤트 종류: {type_name}\n"
        f"이벤트 제목: {title}\n"
        f"AWS 계정 ID: {account_id}\n"
        f"리전: {region}\n"
        f"자산 유형: {resource}\n"
        f"심각도: {severity}\n\n"
        f"보안 팀의 즉각적인 확인 필요"
    )
    
    try:
        # SNS 알림 전송
        response = sns.publish(
            TopicArn='arn:aws:sns:ap-northeast-2:YOUR-ACCOUNT-ID:security-alerts-topic',
            Subject=subject,
            Message=message
        )
        
        print(f"SNS 알림 전송 성공: {response['MessageId']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Alert sent successfully',
                'messageId': response['MessageId']
            })
        }
        
    except Exception as e:
        print(f"SNS 알림 전송 실패: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Failed to send alert',
                'details': str(e)
            })
        }
```

### 설정 요구사항

#### 1. EventBridge 규칙 설정

EventBridge에서 다음 이벤트 패턴으로 규칙을 생성해야 합니다:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": [
      "PrivilegeEscalation:IAMUser/AdministrativePermissions",
      "PrivilegeEscalation:IAMUser/PermissionPolicy",
      "PrivilegeEscalation:IAMUser/UpdateAssumeRolePolicy"
    ]
  }
}
```

#### 2. Lambda 실행 역할 권한

Lambda 함수의 실행 역할에 다음 권한이 필요합니다:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "arn:aws:sns:*:*:security-alerts-topic"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

#### 3. SNS 주제 생성

보안 알림을 받을 SNS 주제를 미리 생성하고 구독을 설정해야 합니다.

---

## 보안 권장사항

### 운영 환경 보안 체크리스트

| 분야 | 실습 환경 | 운영 환경 권장 | 우선순위 |
|------|-----------|----------------|----------|
| 인증 | 기본 액세스 키 | Certificate Authority + MFA | 🔴 High |
| IAM | 데모용 권한 | 최소 권한 원칙 적용 | 🔴 High |
| 네트워크 | 공개 접근 | VPC + 프라이빗 서브넷 | 🔴 High |
| 권한 | 관리자 권한 | 역할 기반 접근 제어 (RBAC) | 🔴 High |
| 모니터링 | 기본 CloudTrail | 실시간 알림 + 자동 대응 | 🟡 Medium |
| 정책 | 단순 정책 | 조건부 정책 + SCP 적용 | 🟡 Medium |

### 핵심 보안 강화 방안

### 1. IAM 정책 기반 예방

#### 조건부 정책 적용
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      }
    }
  ]
}
```

### 2. CloudTrail 모니터링

다음 API 호출에 대한 실시간 모니터링 설정:
- `CreateUser`
- `AttachUserPolicy`
- `CreateAccessKey`
- `PutUserPolicy`

### 3. 정기 감사

- 주기적인 IAM 사용자 및 권한 검토
- 불필요한 관리자 권한 제거
- 액세스 키 순환 정책 적용

### 4. 최소 권한 원칙

- 업무 수행에 필요한 최소한의 권한만 부여
- 임시 역할(Assume Role) 활용
- 다단계 인증(MFA) 필수 적용

---

## 대응 절차

### 1. 즉시 대응
1. 의심스러운 사용자 계정 비활성화
2. 관련 액세스 키 무효화
3. 영향 범위 파악

### 2. 상세 분석
1. CloudTrail 로그 전수 조사
2. 생성된 리소스 확인
3. 데이터 유출 여부 점검

### 3. 복구 및 강화
1. 취약점 패치
2. 보안 정책 강화
3. 모니터링 시스템 개선

---

## 결론

이 공격 시나리오는 AWS 환경에서 자주 발생하는 내부 위협 중 하나입니다. GuardDuty와 Lambda를 활용한 실시간 탐지 시스템을 구축하고, 적절한 예방 조치를 취함으로써 이러한 공격을 효과적으로 방어할 수 있습니다.

정기적인 보안 점검과 지속적인 모니터링을 통해 AWS 환경의 보안을 유지하는 것이 중요합니다.
