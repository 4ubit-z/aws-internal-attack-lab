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
