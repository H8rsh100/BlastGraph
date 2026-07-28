resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_iam_role" "app_role" {
  name = "app_role"
}

resource "aws_iam_policy" "wildcard_policy" {
  name   = "wildcard_policy"
  policy = "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"
}

resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}
