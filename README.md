# aws-internal-attack-lab

AWS 환경에서 보안 공격을 시뮬레이션하고 실시간 탐지/대응 시스템을 구축하는 프로젝트입니다.

## 주요 기능

- **4가지 공격 시나리오** 시뮬레이션
- **실시간 탐지** (CloudTrail, GuardDuty)
- **자동 알림** (EventBridge → Lambda → SNS)
- **로그 분석** (S3 → Glue → Athena)

## 공격 시나리오

1. **EC2 Instance Credentials 탈취** - IMDS를 통한 IAM 자격 증명 탈취
2. **SSM Parameters 복호화** - 암호화된 SSM Parameter 값 탈취
3. **S3 버킷 백도어** - S3 버킷 정책에 공격자 Principal 추가
4. **Lambda 함수 변조** - 기존 Lambda 함수를 악성 코드로 교체

## 기술 스택

- **Infrastructure**: Terraform
- **Cloud**: AWS (EC2, Lambda, S3, SSM, CloudTrail, GuardDuty)
- **Monitoring**: EventBridge, CloudWatch
- **Analysis**: AWS Glue, Amazon Athena
- **Notification**: SNS

## 빠른 시작

### 환경 설정
```bash
# AWS 자격 증명 설정
$env:AWS_ACCESS_KEY_ID='YOUR_ACCESS_KEY'
$env:AWS_SECRET_ACCESS_KEY='YOUR_SECRET_KEY'
```

### 인프라 배포
<li><a href="https://github.com/4ubit-z/aws-internal-attack-lab/tree/dev">테라폼 스켈레톤 코드</a></li>

### 공격 시뮬레이션 
<li><a href="https://github.com/4ubit-z/aws-internal-attack-lab/tree/dev">공격 시나리오 4가지</a></li>

## 프로젝트 구조

```
├── main.tf                 # Terraform 인프라 코드
├── scripts/
│   └── attack/            # 공격 스크립트
└── docs/
    └──서
```

## 필요한 IAM 권한

- IAMFullAccess
- AmazonEC2FullAccess  
- AmazonS3FullAccess
- CloudWatchFullAccess
- AmazonGuardDutyFullAccess
- AWSCloudTrailFullAccess

## 참고 자료

- [Stratus Red Team](https://stratus-red-team.cloud/) - 공격 시나리오 참조

