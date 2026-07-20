variable "BUILD_CREATED" {
  default = "1970-01-01T00:00:00Z"
}

variable "SOURCE_DATE_EPOCH" {
  default = "1784419200"
}

variable "VERSION" {
  default = "0.0.0"
}

variable "VCS_REF" {
  default = "unknown"
}

group "default" {
  targets = ["core"]
}

target "core" {
  context    = "."
  dockerfile = "docker/Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["mycogni/core:${VERSION}"]
  args = {
    BUILD_CREATED = BUILD_CREATED
    VERSION       = VERSION
    VCS_REF       = VCS_REF
  }
}

target "runner-mailbox" {
  context    = "."
  dockerfile = "docker/Dockerfile.runner-mailbox"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["mycogni/runner-mailbox:${VERSION}"]
  args = {
    BUILD_CREATED = BUILD_CREATED
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    VERSION       = VERSION
    VCS_REF       = VCS_REF
  }
}

target "browser-spike" {
  context    = "."
  dockerfile = "docker/Dockerfile.browser"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["mycogni/browser-spike:${VERSION}"]
  args = {
    BUILD_CREATED = BUILD_CREATED
    VERSION       = VERSION
    VCS_REF       = VCS_REF
  }
}
