cat > lab.yaml <<YAML
apiVersion: v1
clusters:
- cluster:
    proxy-url: socks5://localhost:12000
    server: https://api.lab-cloudscale-rma-0.appuio.cloud:6443
  name: c-appuio-lab-cloudscale-rma-0
contexts:
- context:
    cluster: c-appuio-lab-cloudscale-rma-0
    user: c-appuio-lab-cloudscale-rma-0
  name: c-appuio-lab-cloudscale-rma-0
current-context: c-appuio-lab-cloudscale-rma-0
kind: Config
users:
- name: c-appuio-lab-cloudscale-rma-0
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - oc-web-login
      - c-appuio-lab-cloudscale-rma-0
      - --exec-credential
      command: /Users/sebastianwidmer/workspace/kharon/kharon
      env: null
      interactiveMode: IfAvailable
      provideClusterInfo: false
YAML

KUBECONFIG=lab.yaml kubectl get nodes