function handleRegionChange() {
    const regionSelect = document.getElementById('regionSelect');
    // const customRegionInput = document.getElementById('customRegionInput');

    const customCollectorUrl = document.getElementById('customCollectorUrl');
    const customCollectorPort = document.getElementById('customCollectorPort');
  
    if (regionSelect.value === 'custom') {
      customCollectorUrl.style.display = 'block';
      customCollectorPort.style.display = 'block';
    } else {
      customCollectorUrl.style.display = 'none';
      customCollectorPort.style.display = 'none';
    }
  }
  
  function selectRegion(region) {
    document.getElementById('regionSelect').textContent = region;
    // document.getElementById('regionOptions').style.display = 'none';
  }

  function toggleRegionOptions() {
    const options = document.getElementById('regionOptions');
    options.style.display = options.style.display === 'none' ? 'block' : 'none';
  }

  // Close dropdown options when clicking outside
  // document.addEventListener('click', function (event) {
  //   // const options = document.getElementById('regionOptions');
  //   const select = document.getElementById('regionSelect');

  //   if (event.target !== select) {
  //     options.style.display = 'none';
  //   }
  // });
  
  function toggleRegistryInputs(checkboxId, inputsContainerId) {
    const checkbox = document.getElementById(checkboxId);
    const inputsContainer = document.getElementById(inputsContainerId);

    if (checkbox.checked) {
      const registry_fields = ["Internal Registry", "Internal Sysdig Agent Image", "Internal Registry Pull Secret", "Internal Sysdig Runtime Scanner Image", "Sysdig Agent Tag", "Sysdig Runtime Scanner Tag"];
      // Clear existing inputs
      inputsContainer.innerHTML = '';

      // Generate input boxes
      for (let i = 0; i < registry_fields.length; i++) {
        const inputWrapper = document.createElement('div');
        inputWrapper.classList.add('dynamic-input-wrapper');

        const label = document.createElement('label');
        label.textContent = registry_fields[i];

        const input = document.createElement('input');
        input.type = 'text';
        input.name = registry_fields[i];

        inputWrapper.appendChild(label);
        inputWrapper.appendChild(input);

        inputsContainer.appendChild(inputWrapper);
      }
    } else {
      // Clear inputs when unchecked
      inputsContainer.innerHTML = '';
    }
  }
  function toggleProxyInputs(checkboxId, inputsContainerId) {
    const checkbox = document.getElementById(checkboxId);
    const inputsContainer = document.getElementById(inputsContainerId);

    if (checkbox.checked) {
      // Clear existing inputs
      inputsContainer.innerHTML = '';
      const inputWrapper = document.createElement('div');
      inputWrapper.classList.add('dynamic-input-wrapper');

      const label = document.createElement('label');
      label.textContent = 'Proxy Host';

      const input = document.createElement('input');
      input.type = 'text';
      input.name = 'proxy_host';
      input.required = true;

      inputWrapper.appendChild(label);
      inputWrapper.appendChild(input);

      const inputWrapper2 = document.createElement('div');
      inputWrapper2.classList.add('dynamic-input-wrapper');

      const label2 = document.createElement('label');
      label2.textContent = 'Proxy Port';

      const input2 = document.createElement('input');
      input2.type = 'text';
      input2.name = 'proxy_port';
      input2.required = true;

      inputWrapper2.appendChild(label2);
      inputWrapper2.appendChild(input2);

      const inputWrapper3 = document.createElement('div');
      inputWrapper3.classList.add('dynamic-input-wrapper');

      const label3 = document.createElement('label');
      label3.textContent = 'No Proxy List(Comma delimited)';

      const input3 = document.createElement('input');
      input3.type = 'text';
      input3.name = 'no_proxy_list';
      input3.required = true;

      inputWrapper3.appendChild(label3);
      inputWrapper3.appendChild(input3);

      inputsContainer.appendChild(inputWrapper);
      inputsContainer.appendChild(inputWrapper2);
      inputsContainer.appendChild(inputWrapper3);
    } else {
      // Clear inputs when unchecked
      inputsContainer.innerHTML = '';
    }
  }
  function toggleInput(checkboxId, inputId) {
    const checkbox = document.getElementById(checkboxId);
    const inputDiv = document.getElementById(inputId);
    inputDiv.style.display = checkbox.checked ? 'block' : 'none';
  }
  
function displayOutput() {
  // Retrieve user inputs
  const namespaceInput = document.querySelector('#namespaceInput input').value;
  const accessKeyInput = document.querySelector('#accessKeyInput input').value;
  // const regionInput = document.querySelector('#regionInput input').value;
  // const regionInput = document.getElementById('regionSelect').textContent;
  const clusterNameInput = document.querySelector('#clusterNameInput input').value;
  const clusterTagsInput = document.querySelector('#clusterTagsInput input').value;
  const proxyCheckbox = document.getElementById('proxyCheckbox');
  const proxyInput = document.getElementById('proxyInput');
  const inputs = proxyInput.getElementsByTagName('input');
  const registryCheckbox = document.getElementById('registryCheckbox');
  const registryInput = document.getElementById('registryInput');
  const registryInputs = registryInput.getElementsByTagName('input');
  const priorityCheckbox = document.getElementById('priorityCheckbox');
  const priorityInput = document.querySelector('#priorityInput input').value;
  const outputDiv = document.getElementById('output');

  let regionInput;
  let customCollectorUrl;
  let customCollectorPort;
  const regionSelect = document.getElementById('regionSelect');
  if (regionSelect.value === 'custom') {
    regionInput = "custom";
    customCollectorUrl = document.getElementById('customCollectorUrl').value;
    customCollectorPort = document.getElementById('customCollectorPort').value;
  } else {
    regionInput = regionSelect.value;
  }

  // Validate required inputs
  if (!namespaceInput || !accessKeyInput || !regionInput || !clusterNameInput || !clusterTagsInput) {
    alert('Please fill in all required fields.');
    return;
  }


  // Create YAML content
  let yamlContent = `global:
sysdig:
  accessKey: ${accessKeyInput}
  region: ${regionInput}
clusterConfig:
  name: ${clusterNameInput}`;
let nodeAnalyzerYamlContent=`
nodeAnalyzer:
  secure:
    vulnerabilityManagement:
      newEngineOnly: true
  nodeAnalyzer:
    sslVerifyCertificate: false
    imageAnalyzer:
      deploy: false
    benchmarkRunner:
      deploy: false
    hostAnalyzer:
      deploy: false
    hostScanner:
      deploy: false`;
let nodeAnalyzerRuntimeScannerYamlContent=`
    runtimeScanner:
      deploy: true`;
let nodeAnalyzerRuntimeScannerImageSizingContent = `
      settings:
        eveEnabled: false
        maxImageSizeAllowed: "6442450944"
        maxFileSizeAllowed: "500000000"
      eveConnector:
        deploy: false
      resources:
        requests:
          ephemeral-storage: 6Gi
        limits:
          cpu: 1000m
          memory: 4Gi
          ephemeral-storage: 6Gi`;
let agentYamlContent = `
agent:
slim:
  enabled: false
auditLog:
  enabled: false
sysdig:
  settings:
    tags: ${clusterTagsInput}`;
let agentCollectorContent = `
collectorSettings:
  collectorHost: ${customCollectorUrl}
  collectorPort: ${customCollectorPort}
  sslVerifyCertificate: false`;

  if (proxyCheckbox.checked) {
    yamlContent += `
proxy:
  httpProxy: http://${inputs[0].value}:${inputs[1].value}
  httpsProxy: http://${inputs[0].value}:${inputs[1].value}
  noProxy: ${inputs[2].value}`
  agentYamlContent += `
    http_proxy:
      proxy_host: ${inputs[0].value}
      proxy_port: ${inputs[1].value}`;
  };
  if (registryCheckbox.checked) {
    yamlContent += `
imageRegistry: ${registryInputs[0].value}/${registryInputs[1].value}`;
  };
  nodeAnalyzerYamlContent += nodeAnalyzerRuntimeScannerYamlContent;
  yamlContent += agentYamlContent;
  yamlContent += agentCollectorContent;
  if (registryCheckbox.checked) {
    let agentImageYamlContent = `
image:
  repository: ${registryInputs[0].value}/${registryInputs[1].value}
  tag: ${registryInputs[4].value}`;
    let nodeAnalyzerRuntimeScannerImageContent=`
      image:
        repository: ${registryInputs[0].value}/${registryInputs[3].value}
        tag: ${registryInputs[5].value}`;
    nodeAnalyzerYamlContent += nodeAnalyzerRuntimeScannerImageContent;
    nodeAnalyzerYamlContent += nodeAnalyzerRuntimeScannerImageSizingContent;
    yamlContent += agentImageYamlContent;
  };
  yamlContent += nodeAnalyzerYamlContent;

  if (priorityCheckbox.checked) {
    agentYamlContent += `
priorityClassName: ${priorityInput}`;
  }
  // Create a Blob with the YAML content
  const blob = new Blob([yamlContent], { type: 'text/yaml' });

  let outputText = `Install Command<br> helm repo add sysdig https://charts.sysdig.com --force-update <br><br> helm upgrade -i --force sysdig-agent --namespace ${namespaceInput} --create-namespace -f config.yaml sysdig/sysdig-deploy`;
  outputDiv.innerHTML = outputText;
  // Create a temporary <a> element to trigger the download
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'config.yaml';
  link.click();
}