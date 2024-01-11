# DNS
data "aws_route53_zone" "zone" {
  name = var.tfe_domain
}


resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.zone.zone_id
  #name    = "fdo-docker.${data.aws_route53_zone.zone.name}"
  name = "${var.tfe_subdomain}.${data.aws_route53_zone.zone.name}"
  type = "A"
  ttl  = "300"
  #records = ["34.253.52.28"]
  records = [aws_eip.eip.public_ip]
}

# Create Certificates
resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.private_key.private_key_pem
  #email_address   = "dededanutza@gmail.com"
  email_address = var.email
}

resource "acme_certificate" "certificate" {
  account_key_pem = acme_registration.reg.account_key_pem
  #common_name                  = "fdo-docker.${data.aws_route53_zone.zone.name}"
  #subject_alternative_names    = ["fdo-docker.${data.aws_route53_zone.zone.name}"]
  common_name                  = "${var.tfe_subdomain}.${data.aws_route53_zone.zone.name}"
  subject_alternative_names    = ["${var.tfe_subdomain}.${data.aws_route53_zone.zone.name}"]
  disable_complete_propagation = true

  dns_challenge {
    provider = "route53"
    config = {
      AWS_HOSTED_ZONE_ID = data.aws_route53_zone.zone.zone_id
    }
  }
}

# Add my certificates to a S3 Bucket
resource "aws_s3_bucket" "s3bucket" {
  bucket = var.certs_bucket

  tags = {
    Name        = "Daniela FDO Bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_object" "object" {
  for_each = toset(["certificate_pem", "issuer_pem", "private_key_pem"])
  bucket   = aws_s3_bucket.s3bucket.bucket
  key      = "ssl-certs/${each.key}"
  content  = lookup(acme_certificate.certificate, "${each.key}")
}

resource "aws_s3_object" "object_full_chain" {
  bucket  = aws_s3_bucket.s3bucket.bucket
  key     = "ssl-certs/full_chain"
  content = "${acme_certificate.certificate.certificate_pem}${acme_certificate.certificate.issuer_pem}"
}

# Add my TFE FDO license to a S3 Bucket
resource "aws_s3_bucket" "s3bucket_license" {
  bucket = var.license_bucket

  tags = {
    Name        = "Daniela FDO License"
    Environment = "Dev"
  }
}

resource "aws_s3_object" "object_license" {
  bucket = aws_s3_bucket.s3bucket_license.bucket
  key    = var.license_filename
  source = var.license_filename
}

# Create network
resource "aws_vpc" "vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "daniela-vpc"
  }
}

resource "aws_subnet" "publicsub" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "daniela-public-subnet"
  }
}

resource "aws_subnet" "privatesub" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}c"

  tags = {
    Name = "daniela-private-subnet"
  }
}


resource "aws_internet_gateway" "internetgw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "daniela-internet-gateway"
  }
}

resource "aws_route_table" "route" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internetgw.id
  }

  tags = {
    Name = "daniela-route"
  }
}

resource "aws_route_table_association" "route_association" {
  subnet_id      = aws_subnet.publicsub.id
  route_table_id = aws_route_table.route.id
}

resource "aws_security_group" "securitygp" {

  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "https-access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ssh-access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ssh-access"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "egress-rule"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    type = "daniela-security-group"
  }
}


resource "aws_network_interface" "nic" {
  subnet_id       = aws_subnet.publicsub.id
  security_groups = [aws_security_group.securitygp.id]
}

# resource "aws_network_interface_sg_attachment" "sg_attachment" {
#   security_group_id    = aws_security_group.securitygp.id
#   network_interface_id = aws_instance.instance.primary_network_interface_id
# }

resource "aws_eip" "eip" {
  instance = aws_instance.instance.id
  domain   = "vpc"
}

# Create roles and policies to attach to the instance
resource "aws_iam_role" "daniela-role" {
  name = "daniela-role-docker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_instance_profile" "daniela-profile" {
  name = "daniela-profile-docker"
  role = aws_iam_role.daniela-role.name
}

resource "aws_iam_role_policy" "daniela-policy" {
  name = "daniela-policy-docker"
  role = aws_iam_role.daniela-role.id

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : "s3:ListBucket",
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Resource" : [
          "arn:aws:s3:::*/*"
        ]
      }
    ]
  })
}

# Create EC2 instance
resource "aws_instance" "instance" {
  #ami                  = "ami-0694d931cee176e7d" # eu-west-1
  ami                  = "ami-0ff1c68c6e837b183" # eu-west-2 
  instance_type        = "t2.xlarge"
  iam_instance_profile = aws_iam_instance_profile.daniela-profile.name

  credit_specification {
    cpu_credits = "unlimited"
  }

  key_name = var.key_pair

  root_block_device {
    volume_size = 50
  }

  user_data = templatefile("fdo_ent.yaml", {
    license          = var.license_filename,
    tfe_version      = var.tfe_version,
    tfe_hostname     = var.tfe_hostname,
    enc_password     = var.enc_password,
    email            = var.email,
    username         = var.username,
    password         = var.password,
    certs_bucket     = var.certs_bucket,
    license_bucket   = var.license_bucket,
    license_filename = var.license_filename,
    db_username      = var.db_username,
    db_password      = var.db_password,
    db_host          = aws_db_instance.tfe-db.endpoint,
    db_name          = var.db_name,
    storage_bucket   = var.storage_bucket,
    aws_region       = var.aws_region

  })

  network_interface {
    network_interface_id = aws_network_interface.nic.id
    device_index         = 0
  }

  tags = {
    Name = "daniela-tfe-fdodocker"
  }

}


# Create External Services: AWS S3 Bucket
resource "aws_s3_bucket" "s3bucket_data" {
  bucket        = var.storage_bucket
  force_destroy = true

  tags = {
    Name        = "Daniela FDO Storage"
    Environment = "Dev"
  }
}

# Create External Services: Postgres 14.x DB
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "daniela-db-subnetgroup"
  subnet_ids = [aws_subnet.publicsub.id, aws_subnet.privatesub.id]

  tags = {
    Name = "daniela-db-subnet-group "
  }
}

resource "aws_db_instance" "tfe-db" {
  allocated_storage      = 400
  identifier             = var.db_identifier
  db_name                = var.db_name
  engine                 = "postgres"
  engine_version         = "14.9"
  instance_class         = "db.m5.xlarge"
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = "default.postgres14"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.securitygp.id]
}