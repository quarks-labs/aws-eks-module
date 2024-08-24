terraform {
  backend "local" {
    workspace_dir = ".backend"
    path = "terrform.tfstate"
  }
}