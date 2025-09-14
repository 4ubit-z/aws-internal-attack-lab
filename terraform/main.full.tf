# 1.리전 설정
provider "aws" {
    region = "ap-northeast-2"
}
# 2.VPC 생성
resource "aws_vpc" "main_vpc"{
    cidr_block ="10.0.0.0/16" 

    tags = {
        Name =" Main_VPC"
    }
}
# 2.1 Public Subnet 생성
resource "aws_subnet" "public_subnet"{
    vpc_id = aws_vpc.main_vpc.id
    cidr_block = "10.0.1.0/24"
    map_public_ip_on_launch = true
    availability_zone = "ap-northeast-2a"
    tags = {
        Name ="PublicSubnet"
    }
}
# 2.2 Private Subnet 생성
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false 
  availability_zone       = "ap-northeast-2a"

  tags = {
    Name = "PrivateSubnet"
  }
}
# 2.3 인터넷 게이트웨이 생성 (퍼블릭 서브넷용)
resource "aws_internet_gateway" "main_gw"{
    vpc_id = aws_vpc.main_vpc.id
}
# 2.4 NAT 게이트웨이 생성
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}
# 2.5 NAT 게이트웨이 생성 (퍼블릭 서브넷에 배포)
resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id

  depends_on = [aws_internet_gateway.main_gw]  # 의존성 추가

  tags = {
    Name = "MyNATGateway"
  }
}
# 2.6 라우팅 테이블 설정 (퍼블릭 서브넷용)
resource "aws_route_table" "public_rt"{
    vpc_id = aws_vpc.main_vpc.id

    route{
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.main_gw.id
    }
    tags = {
        Name = "PublicRouteTable"
    }
}

# 2.7 서브넷과 라우팅 테이블 연결
resource "aws_route_table_association" "public_assoc"{
    subnet_id = aws_subnet.public_subnet.id
    route_table_id = aws_route_table.public_rt.id
}

# 2.8 프라이빗 라우팅 테이블 생성 (NAT 게이트웨이 연결)
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "PrivateRouteTable"
  }
}
# 2.9 프라이빗 서브넷과 라우트 테이블 연결
resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_rt.id
}
# 2.10 보안그룹 생성(SSH 및 HTTP허용,RDP)
resource "aws_security_group" "allow_ssh_http"{
    vpc_id = aws_vpc.main_vpc.id

    # SSH 허용
    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    #HTTP 허용
    ingress {
        from_port = 80
        to_port = 80
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    # RDP 허용
    ingress {
      from_port   = 3389
      to_port     = 3389
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"] 
    }
    # 9001포트 허용
    ingress {
    from_port = 9001
    to_port   = 9001
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # or 제한된 IP
    }

    #모든 아웃바운드 트래픽 허용
    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
        Name = "AllowSSHAndHTTP"
    }
}
# 2.11 키 페어 생성
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_key" {
  key_name   = "ec2-default-key"  
  public_key = tls_private_key.ec2_key.public_key_openssh
}

resource "local_file" "private_key_pem" { #로컬 파일에 키파일 저장
  content         = tls_private_key.ec2_key.private_key_pem
  filename        = "${path.module}/ec2-default-key.pem"
  file_permission = "0400"
}

# 3. Ec2 생성
# 3.1 퍼블릭 서브넷 / Kali(공격자)
resource "aws_instance" "attacker_ec2" {
  ami           = "ami-083247485ea55d01b"
  instance_type = "t3.medium" 
  subnet_id     = aws_subnet.public_subnet.id
  security_groups = [aws_security_group.allow_ssh_http.id]
  key_name = aws_key_pair.ec2_key.key_name

  user_data = <<-EOF
#!/bin/bash
# 전체 시스템 업그레이드
apt update -y
apt upgrade -y

# 필수 도구 설치
apt install -y net-tools
apt install -y xfce4 xfce4-goodies
apt install -y xrdp

# xrdp 서비스 활성화
systemctl enable xrdp
systemctl start xrdp

# RDP GUI 세션 설정
echo "xfce4-session" > /home/kali/.xsession
chmod 644 /home/kali/.xsession
chown kali:kali /home/kali/.xsession

# Kali 사용자 비밀번호 설정
echo 'kali:kali' | chpasswd
EOF


  tags = {
    Name = "Attacker-Kali"
  }
}

# 3.2 퍼블릭 서브넷 / bastion_host
resource "aws_instance" "bastion" {
  ami           = "ami-0d5bb3742db8fc264"
  instance_type = "t2.micro" 
  subnet_id     = aws_subnet.public_subnet.id
  security_groups = [aws_security_group.allow_ssh_http.id]
  key_name = aws_key_pair.ec2_key.key_name

  tags = {
    Name = "bastion"
  }
}


# IAM Role (타겟 EC2에 부여)
resource "aws_iam_role" "target_instance_role" {
  name = "target-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

# IAM 정책 (예: S3 읽기)
resource "aws_iam_policy" "s3_read_policy" {
  name = "s3-read-access"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
    {
      "Action": "s3:ListAllMyBuckets",
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": "s3:ListBucket",
      "Effect": "Allow",
      "Resource": "*"
    }]
  })
}

# 정책 → 역할 연결
resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.target_instance_role.name
  policy_arn = aws_iam_policy.s3_read_policy.arn
}

# EC2에서 사용할 Instance Profile 생성
resource "aws_iam_instance_profile" "target_profile" {
  name = "target-instance-profile"
  role = aws_iam_role.target_instance_role.name
}

# 3.3 프라이빗 서브넷 / Ubuntu
resource "aws_instance" "target_private_ec2" {
  ami           = "ami-0d5bb3742db8fc264"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.private_subnet.id
  security_groups = [aws_security_group.allow_ssh_http.id]
  key_name = aws_key_pair.ec2_key.key_name
  iam_instance_profile = aws_iam_instance_profile.target_profile.name
  

    user_data = <<-EOF
#!/bin/bash
# 전체 시스템 업그레이드
apt update -y
apt upgrade -y

# ubuntu 사용자 비밀번호 설정
echo 'ubuntu:ubuntu' | chpasswd
EOF
  metadata_options {
      http_tokens   = "optional"   # ← IMDSv1 허용
      http_endpoint = "enabled"
    }
  tags = {
    Name = "Private-Target"
  }
}


# 4. 랜덤 문자열 생성 (S3 버킷 이름을 유니크하게 하기 위함)
resource "random_id" "s3_id" {
  byte_length = 4
}

# 4.1. S3 버킷 생성 (보안 이벤트 저장)
resource "aws_s3_bucket" "security_logs" {
  # 버킷 이름은 반드시 소문자만 포함되어야 하므로 lower() 처리
  bucket = "security-reports-logs-${lower(random_id.s3_id.hex)}"
}

# 4.2. AWS 계정 ID 가져오기
data "aws_caller_identity" "current" {}

# 4.3. S3 버킷 정책 (CloudTrail 로그 기록 허용 & 삭제 방지)
resource "aws_s3_bucket_policy" "security_logs_policy" {
  bucket = aws_s3_bucket.security_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "CloudTrailPutObject",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "arn:aws:s3:::${aws_s3_bucket.security_logs.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "CloudTrailGetBucketAcl",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "arn:aws:s3:::${aws_s3_bucket.security_logs.bucket}"
      },
      {
        Sid       = "DenyDeleteObject",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:DeleteObject",
        Resource  = "arn:aws:s3:::${aws_s3_bucket.security_logs.bucket}/*"
      }
    ]
  })
}


#  5. CloudWatch 로그 그룹 생성 (실시간 탐지용)
resource "aws_cloudwatch_log_group" "security_log_group" {
  name = "/aws/security/logs"
  retention_in_days = 3
}

#  6. 탐지 시스템 구성
## 6.1 CloudTrail 설정 (AWS API 호출 기록 저장)
resource "aws_cloudtrail" "security_trail" {
  name                           = "security-trail"
  s3_bucket_name                 = aws_s3_bucket.security_logs.id
  include_global_service_events  = true
  is_multi_region_trail          = true

  depends_on = [
    aws_s3_bucket_policy.security_logs_policy
  ]
}

## 6.2 GuardDuty 활성화 (비정상 활동 감지)
resource "aws_guardduty_detector" "GuardDuty" {
  enable = true
}

## 6.3 Security Hub 활성화 (통합 관리)
resource "aws_securityhub_account" "security_hub" {}

#  7. Lambda 설정 (CloudWatch + S3 동시 저장)
## 7.1 Lambda 실행을 위한 IAM 역할 생성
resource "aws_iam_role" "lambda_exec" {
  name = "lambda_security_log_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

## 7.2 Lambda가 CloudWatch Logs 및 S3에 접근할 수 있도록 정책 부여
resource "aws_iam_policy" "lambda_logging_policy" {
  name        = "lambda_logging_policy"
  description = "Policy for Lambda to log security events"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::${aws_s3_bucket.security_logs.id}/*"
    }
  ]
}
EOF
}

## 7.3 IAM 역할에 정책 연결
resource "aws_iam_role_policy_attachment" "lambda_logging_attachment" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_logging_policy.arn
}

## 7.4 Lambda 함수 생성 (CloudWatch + S3 동시 저장)
resource "aws_lambda_function" "security_lambda" {
  function_name = "log_security_events"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.9"
  handler       = "lambda_function.lambda_handler"

  # Lambda 코드 업로드 (ZIP 파일 로컬 수동 업로드)
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")

  environment {
    variables = {
      LOG_GROUP = "/aws/security/logs"
      S3_BUCKET = aws_s3_bucket.security_logs.id
    }
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.security_alert.arn

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "AllowEventBridgePublish",
        Effect: "Allow",
        Principal: {
          Service: "events.amazonaws.com"
        },
        Action: "sns:Publish",
        Resource: aws_sns_topic.security_alert.arn
      }
    ]
  })
}

# 7.5 Lambda 함수 생성 (eventBridge + Lambda + SNS)
# SNS Topic 생성
resource "aws_sns_topic" "security_alert" {
  name  = "security-alerts-topic"
}
# SNS 이메일 구독자 등록
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alert.arn
  protocol = "email"
  endpoint = "aubit@naver.com"
}
# IAM 역할 (Lambda 실행용)
resource "aws_iam_role" "lambda_alert_role" {
  name = "lambda_s3_alert_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# SNS publish 권한
resource "aws_iam_policy" "lambda_alert_sns_policy" {
  name = "lambda_s3_alert_sns_policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["sns:Publish"],
      Resource = "arn:aws:sns:ap-northeast-2:867344475403:security-alerts-topic"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_alert_attach" {
  role       = aws_iam_role.lambda_alert_role.name
  policy_arn = aws_iam_policy.lambda_alert_sns_policy.arn
}

#  Lambda s3_backdoor 함수 정의 
resource "aws_lambda_function" "s3_backdoor_alert_lambda" {
  function_name = "s3-backdoor-alert"
  handler       = "lambda_s3_alert.lambda_handler"
  runtime       = "python3.9"
  role          = aws_iam_role.lambda_alert_role.arn

  filename         = "${path.module}/lambda_s3_alert.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_s3_alert.zip")
}
# Lambda guardduty 함수 정의
resource "aws_lambda_function" "guardduty_privilege_lambda" {
  function_name = "guardduty-privilege-alert"
  handler       = "lambda_guardduty_privilege_alert.lambda_handler"
  runtime       = "python3.9"
  role          = aws_iam_role.lambda_alert_role.arn
  filename         = "${path.module}/lambda_guardduty_privilege_alert.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_guardduty_privilege_alert.zip")

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alert.arn
    }
  }
}
# Lambda lambda_overwirte_alert 함수 정의
resource "aws_lambda_function" "lambda_overwrite_alert" {
  function_name = "lambda-overwrite-alert"
  handler       = "lambda_overwrite_alert.lambda_handler"
  runtime       = "python3.9"
  role          = aws_iam_role.lambda_alert_role.arn

  filename         = "${path.module}/lambda_overwrite_alert.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_overwrite_alert.zip")

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alert.arn
    }
  }
}


# EventBridge 룰 - PutBucketPolicy 이벤트 감지
resource "aws_cloudwatch_event_rule" "s3_backdoor_event_rule" {
  name = "detect-putbucketpolicy-s3-backdoor"
  event_pattern = jsonencode({
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["PutBucketPolicy"]
    }
  })
}
# EventBridge 룰 - GuardDuty 권한 상승 탐지용
resource "aws_cloudwatch_event_rule" "guardduty_privilege_rule" {
  name = "guardduty-privilege-detection"

  event_pattern = jsonencode({
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "PrivilegeEscalation:IAMUser/PermissionPolicy",
        "PrivilegeEscalation:IAMUser/UpdateAssumeRolePolicy",
        "Policy:IAMUser/RootCredentialUsage" 
      ]
    }
  })
}
# EventBridge 룰 - UpdateFunctionCode 이벤트 탐지
resource "aws_cloudwatch_event_rule" "lambda_overwrite_event_rule" {
  name = "detect-lambda-overwrite"

  event_pattern = jsonencode({
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["UpdateFunctionCode"]
    }
  })
}

# Lambda 실행 권한 / s3_backdoor 
resource "aws_lambda_permission" "s3_backdoor_lambda_permission" {
  statement_id  = "AllowEventBridgeInvokeS3Backdoor"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_backdoor_alert_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_backdoor_event_rule.arn
}
# Lambda 실행 권한 / Gaurdduty 
resource "aws_lambda_permission" "guardduty_lambda_permission" {
  statement_id  = "AllowGuardDutyEventInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_privilege_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_privilege_rule.arn
}
# Lambda 실행 권한 / Lambda_overwrite
resource "aws_lambda_permission" "lambda_overwrite_permission" {
  statement_id  = "AllowEventBridgeInvokeLambdaOverwrite"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_overwrite_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_overwrite_event_rule.arn
}


# EventBridge → Lambda 연결 / s3_backdoor
resource "aws_cloudwatch_event_target" "s3_backdoor_lambda_target" {
  rule = aws_cloudwatch_event_rule.s3_backdoor_event_rule.name
  arn  = aws_lambda_function.s3_backdoor_alert_lambda.arn
}

# EventBridge → Lambda 연결 / Guardduty 
resource "aws_cloudwatch_event_target" "guardduty_lambda_target" {
  rule = aws_cloudwatch_event_rule.guardduty_privilege_rule.name
  arn  = aws_lambda_function.guardduty_privilege_lambda.arn
}

# EventBridge → Lambda 연결 / Lambda_overwirte
resource "aws_cloudwatch_event_target" "lambda_overwrite_target" {
  rule = aws_cloudwatch_event_rule.lambda_overwrite_event_rule.name
  arn  = aws_lambda_function.lambda_overwrite_alert.arn
}



# 9 로그탐지

# 9.1 Athena 쿼리 결과 저장 버킷 생성
resource "aws_s3_bucket" "athena_output" {
  bucket = "athena-query-results-${random_id.s3_id.hex}"
}
# 9.2 Glue에서 사용할 데이터베이스 생성 (Athena에서도 사용됨)
resource "aws_glue_catalog_database" "cloudtrail_db" {
  name = "cloudtrail_db"
}

# 9.3 Glue Crawler가 사용할 IAM 역할 생성
resource "aws_iam_role" "glue_crawler_role" {
  name = "glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "glue.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}
# Glue Crawler Role에 S3 Read 권한 부여
resource "aws_iam_role_policy" "glue_s3_read_policy" {
  name = "glue-s3-read-policy"
  role = aws_iam_role.glue_crawler_role.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.security_logs.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.security_logs.bucket}/*"
        ]
      }
    ]
  })
}


# 9.4 Glue Crawler에 S3 및 Glue 작업 권한 부여
resource "aws_iam_role_policy_attachment" "glue_s3_access" {
  role       = aws_iam_role.glue_crawler_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

# 9.5 Glue Crawler 정의
# CloudTrail 로그가 저장된 S3 경로를 자동 분석하여 테이블 생성
resource "aws_glue_crawler" "cloudtrail_crawler" {
  name          = "cloudtrail-crawler"                                      # 크롤러 이름
  role          = aws_iam_role.glue_crawler_role.arn                        # 실행 역할
  database_name = aws_glue_catalog_database.cloudtrail_db.name             # 결과 저장할 DB

  # 크롤링할 대상 S3 경로 설정 (CloudTrail 로그 위치)
  s3_target {
    path = "s3://${aws_s3_bucket.security_logs.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/"
  }

  table_prefix = "cloudtrail_logs_crawler_"  # 자동 생성 테이블 앞에 붙을 prefix

  # 크롤링 주기 (null → 수동 실행)
  schedule = null

  # 테이블/파티션 변경 시 정책
  schema_change_policy {
    delete_behavior = "LOG"             # 삭제는 로그만 남기고 무시
    update_behavior = "UPDATE_IN_DATABASE"  # 변경 시 DB 업데이트
  }

  # Glue 크롤러 추가 설정
  configuration = jsonencode({
    Version = 1.0,
    CrawlerOutput = {
      Partitions = { AddOrUpdateBehavior = "InheritFromTable" }
    }
  })

  # S3 버킷 정책 및 리소스 생성 순서 보장
  depends_on = [
    aws_s3_bucket.security_logs,
    aws_s3_bucket_policy.security_logs_policy
  ]
}
