# Intentionally insecure Terraform configuration for testing

# Security Group with overly permissive rules
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "Example security group"

  # BAD: Allows all inbound traffic
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # BAD: Allows all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# S3 bucket without encryption
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # BAD: Public access

  # Missing: Server-side encryption
  # Missing: Versioning
  # Missing: Logging
}

# RDS without encryption
resource "aws_db_instance" "example" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "admin"
  password             = "password123"  # BAD: Hardcoded password
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  publicly_accessible  = true  # BAD: Publicly accessible

  # Missing: storage_encrypted = true
  # Missing: backup configuration
}

# IAM policy that's too permissive
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example IAM policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"  # BAD: Allows all actions
        Resource = "*"  # BAD: On all resources
      }
    ]
  })
}
