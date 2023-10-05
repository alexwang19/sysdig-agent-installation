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
  updateOutput()
}

function selectRegion(region) {
  document.getElementById('regionSelect').textContent = region;
  // document.getElementById('regionOptions').style.display = 'none';
  updateOutput()
}

function toggleRegionOptions() {
  const options = document.getElementById('regionOptions');
  options.style.display = options.style.display === 'none' ? 'block' : 'none';
  updateOutput()
}

// function handlePlatformChange() {
//   const regionSelect = document.getElementById('platformSelect');
//   updateOutput()
// }

// function handleEnvironmentChange() {
//   const regionSelect = document.getElementById('environmentSelect');
//   updateOutput()
// }

// Close dropdown options when clicking outside
// document.addEventListener('click', function (event) {
//   // const options = document.getElementById('regionOptions');
//   const select = document.getElementById('regionSelect');

//   if (event.target !== select) {
//     options.style.display = 'none';
//   }
// });

function toggleRegistryInputs(checkboxId, inputsContainerId) {
  let params = generateUserInputParamObject()
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);

  if (checkbox.checked) {
    const registry_fields = ["Internal Registry", "Internal Registry Pull Secret", "Internal Sysdig Agent Image", "Sysdig Agent Tag", "Internal Sysdig Runtime Scanner Image", "Sysdig Runtime Scanner Tag"];
    const registry_placeholders = ["quay.io", "", "sysdig/agent", "sysdig/vuln-runtime-scanner", params.agentTagsSelect.value, params.runtimeScannerTagsSelect.value];
    // Clear existing inputs
    inputsContainer.innerHTML = '';

    // Generate input boxes
    for (let i = 0; i < registry_fields.length; i++) {
      inputsContainer.appendChild(createTextInput(registry_fields[i], registry_fields[i], false, registry_placeholders[i]));
    }
  } else {
    // Clear inputs when unchecked
    inputsContainer.innerHTML = '';
  }
  updateOutput()
}

function toggleProxyInputs(checkboxId, inputsContainerId) {
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);

  if (checkbox.checked) {
    // Clear existing inputs
    inputsContainer.innerHTML = '';

    inputsContainer.appendChild(createTextInput('Proxy Host', 'proxy_host', true, 'replacewithyourproxy.com'));
    inputsContainer.appendChild(createTextInput('Proxy Port', 'proxy_port', true, '1234'));
    inputsContainer.appendChild(createTextInput('No Proxy List(Comma delimited)', 'no_proxy_list', true, 'CLUSTER_IP\\,replacewithyournoproxyhost.com\\,1.2.3.4'));
  } else {
    // Clear inputs when unchecked
    inputsContainer.innerHTML = '';
  }
  updateOutput()
}

function toggleNodeAnalyzerInputs(checkboxId, inputsContainerId) {
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);
  inputsContainer.style.paddingLeft = '20px'

  if (checkbox.checked) {
    // Clear existing inputs
    inputsContainer.innerHTML = '';

    inputsContainer.appendChild(createCheckboxInput('Install Host Scanner (V2 Scanning Engine)', 'deploy_host_scanner'));
    inputsContainer.appendChild(createCheckboxInput('Install Runtime Scanner (V2 Scanning Engine)', 'deploy_runtime_scanner'));
    inputsContainer.appendChild(createCheckboxInput('Install Image Analyzer (V1 Scanning Engine)', 'deploy_image_analyzer'));
    inputsContainer.appendChild(createCheckboxInput('Install Host Analyzer (V1 Scanning Engine)', 'deploy_host_analyzer'));
    inputsContainer.appendChild(createCheckboxInput('Install Benchmark Runner', 'deploy_benchmark_runner'));
  } else {
    // Clear inputs when unchecked
    inputsContainer.innerHTML = '';
  }
  updateOutput()
}

//customize these functions as features get added
function toggleKspmInputs(checkboxId, inputsContainerId) {
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);
  inputsContainer.style.paddingLeft = '20px'
  updateOutput()
}

//customize these functions as features get added
function toggleAdmissionControllerInputs(checkboxId, inputsContainerId) {
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);
  inputsContainer.style.paddingLeft = '20px'
  updateOutput()
}

//customize these functions as features get added
function toggleRapidResponseInputs(checkboxId, inputsContainerId) {
  const checkbox = document.getElementById(checkboxId);
  const inputsContainer = document.getElementById(inputsContainerId);
  inputsContainer.style.paddingLeft = '20px'
  updateOutput()
}

//customize these functions as features get added
function createTextInput(labelText, inputName, required, value) {
  const inputWrapper = document.createElement('div');
  inputWrapper.classList.add('dynamic-input-wrapper');

  const label = document.createElement('label');
  label.textContent = labelText;

  const input = document.createElement('input');
  input.type = 'text';
  input.name = inputName;
  input.required = required;
  input.value = value;
  input.oninput = updateOutput;

  inputWrapper.appendChild(label);
  inputWrapper.appendChild(input);

  return inputWrapper
}

function createCheckboxInput(labelText, inputId) {
  const inputWrapper = document.createElement('div');
  inputWrapper.classList.add('dynamic-input-wrapper');

  const label = document.createElement('label');
  label.textContent = "  " + labelText;

  const input = document.createElement('input');
  input.type = 'checkbox';
  input.id = inputId;
  input.onchange = updateOutput;

  inputWrapper.appendChild(label);
  label.prepend(input);

  return inputWrapper
}

function toggleInput(checkboxId, inputId) {
  const checkbox = document.getElementById(checkboxId);
  const inputDiv = document.getElementById(inputId);
  inputDiv.style.display = checkbox.checked ? 'block' : 'none';
  updateOutput()
}

function setClusterName(params) {
  let clusterName = "";
  if (params.businessUnit != ""){
    clusterName += params.businessUnit + "-";
  }
  if (params.platform != "") {
    clusterName += params.platform + "-";
  }
  if (params.environment != "") {
    clusterName += params.environment + "-";
  }
  if (params.vastId != "") {
    clusterName += params.vastId + "-";
  }
  if (params.vsadId != "") {
    clusterName += params.vsadId;
  }
  return clusterName
}

function setHelmCommandGlobalConfigs(params) {
  let helmCommandGlobalConfigs = "";
  helmCommandGlobalConfigs += "<br>&nbsp;&nbsp; --set global.clusterConfig.name=" + setClusterName(params) + " \\";
  helmCommandGlobalConfigs += "<br>&nbsp;&nbsp; --set global.sysdig.region=us3" + " \\";
  helmCommandGlobalConfigs += "<br>&nbsp;&nbsp; --set global.sysdig.accessKey=" + params.accessKeyInput + " \\";
  if (params.proxyCheckbox.checked) {
    helmCommandGlobalConfigs += "<br>&nbsp&nbsp; --set global.proxy.httpProxy=http://" + params.proxyInputs[0].value + ":" + params.proxyInputs[1].value + " \\";
    helmCommandGlobalConfigs += "<br>&nbsp&nbsp; --set global.proxy.httpsProxy=http://" + params.proxyInputs[0].value + ":" + params.proxyInputs[1].value + " \\";
    helmCommandGlobalConfigs += "<br>&nbsp&nbsp; --set global.proxy.noProxy=" + params.proxyInputs[2].value + " \\";
  }

  return helmCommandGlobalConfigs
}

function setGlobalConfigs(params) {
  let globalConfigs = {
    global: {
      sysdig: {
        accessKey: params.accessKeyInput,
        region: "us3",
      },
      clusterConfig: {
        name: setClusterName(params),
      },
      // kspm: {
      //   deploy: params.kspmCheckbox.checked
      // }
    }
  }

  // if (Object.keys(params.clusterTags).length > 0) {
  //   globalConfigs.global.sysdig.tags = params.clusterTags
  // }

  if (params.registryCheckbox.checked) {
    globalConfigs.global.imageRegistry = params.registryInputs[0].value ;
  }

  if (params.proxyCheckbox.checked) {
    globalConfigs.global.proxy = {
      httpProxy: "http://" + params.proxyInputs[0].value + ":" + params.proxyInputs[1].value,
      httpsProxy: "http://" + params.proxyInputs[0].value + ":" + params.proxyInputs[1].value,
      noProxy: params.proxyInputs[2].value
    }
  }

  return globalConfigs
}

function setAgentConfigs(params) {
  // let agentMemory = '187Mi'
  // if (params.agentMemoryInput.value !== ""){
  //   agentMemory = params.agentMemoryInput.value + 'Mi'
  // }
  let agentConfigs = {
    agent: {
      slim: {
        enabled: false,
      },
      auditLog: {
        enabled: false,
      },
      // resources: {
      //   requests: {
      //     cpu: '150m',
      //     memory: '187Mi'
      //   },
      //   limits: {
      //     cpu: '500m',
      //     memory: agentMemory,
      //   }
      // }
    },
  }

  // if (params.regionInput === "custom") {
  //   agentConfigs.agent.collectorSettings = {
  //     collectorHost: params.customCollectorUrl,
  //     collectorPort: params.customCollectorPort,
  //     sslVerifyCertificate: false,
  //   }
  // }

  if (params.proxyCheckbox.checked) {
    agentConfigs.agent.sysdig= {
        settings: {
          http_proxy: {
            proxy_host: params.proxyInputs[0].value,
            proxy_port: params.proxyInputs[1].value,
        }
      }
    }
  }

  if (params.registryCheckbox.checked) {
    agentConfigs.agent.image = {
      repository: params.registryInputs[0].value + "/" + params.registryInputs[2].value,
      tag: params.registryInputs[5].value,
    }
    if (params.registryInputs[1].value != "") {
      agentConfigs.agent.image = {
        pullSecrets: params.registryInputs[1].value,
      }
    }
  }
  else {
    agentConfigs.agent.image = {
      tag: params.agentTagsSelect.value,
    }
  }

  if (params.platform === "gke") {
    agentConfigs.agent.ebpf = {
      enabled: true,
    }
  }

  // if (params.priorityCheckbox.checked) {
  //   agentConfigs.agent.priorityClassName = params.priorityInput
  // }

  // if (params.agentProfileInput === "Monitor-only") {
  //   agentConfigs.agent.monitor = { enabled: true }
  //   agentConfigs.agent.secure = { enabled: false }
  // } else if (params.agentProfileInput === "Secure-only") {
  //   agentConfigs.agent.monitor = { enabled: false }
  //   agentConfigs.agent.secure = { enabled: true }
  //   agentConfigs.agent.sysdig.settings["60s_flush_enable"] = true
  // } else if (params.agentProfileInput === "Secure light") {
  //   agentConfigs.agent.monitor = { enabled: false }
  //   agentConfigs.agent.secure = { enabled: true }
  //   agentConfigs.agent.sysdig.settings.feature = { mode: "secure_light" }
  //   agentConfigs.agent.sysdig.settings["60s_flush_enable"] = true
  // }

  return agentConfigs
}


function setHelmCommandAgentConfigs(params) {
  let helmCommandAgentConfigs = "";
  helmCommandAgentConfigs += "<br>&nbsp&nbsp; --set agent.sysdig.settings.tags=" + "cluster:" + params.businessUnit + "-" + 
  params.platform + "-" + params.environment + "-" + params.vastId + "-" + params.vsadId + "\\," +
   "<br>" + "vz-vsadid:" + params.vsadId +"\\," + "vz-vastid:" + params.vastId + " \\";
  
  if (params.platform === "gke") {
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.ebpf.enabled=true \\";
  }

  if (params.proxyCheckbox.checked) {
    helmCommandAgentConfigs += "<br>&nbsp&nbsp; --set agent.sysdig.settings.http_proxy.proxy_host=" + params.proxyInputs[0].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp&nbsp; --set agent.sysdig.settings.http_proxy.proxy_port=" + params.proxyInputs[1].value + " \\";

  } 

  if (params.registryCheckbox.checked) {
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.image.tag=" + params.registryInputs[3].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.image.registry=" + params.registryInputs[0].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.image.repository=" + params.registryInputs[2].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set nodeAnalyzer.image.registry=" + params.registryInputs[0].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set nodeAnalyzer.nodeAnalyzer.runtimeScanner.image.repository=" + params.registryInputs[4].value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set nodeAnalyzer.nodeAnalyzer.runtimeScanner.image.tag=" + params.registryInputs[5].value + " \\";
    if (params.registryInputs[1].value != ""){
      helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.image.pullSecrets=" + params.registryInputs[1].value + " \\";
      helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set nodeAnalyzer.nodeAnalyzer.pullSecrets=" + params.registryInputs[1].value + " \\";
    }
  }
  else {
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set agent.image.tag=" + params.agentTagsSelect.value + " \\";
    helmCommandAgentConfigs += "<br>&nbsp;&nbsp; --set nodeAnalyzer.nodeAnalyzer.runtimeScanner.image.tag=" + params.runtimeScannerTagsSelect.value + " \\";
  }

  // if (params.priorityCheckbox.checked) {
    
  // }
  // updateOutput()

  return helmCommandAgentConfigs
}

function setNodeAnalyzerConfigs(params) {
  let nodeAnalyzerConfigs = {
    nodeAnalyzer: {
      enabled: true,
      nodeAnalyzer: {
        imageAnalyzer: {
          deploy: false,
        },
        benchmarkRunner: {
          deploy: false,
        },
        hostAnalyzer: {
          deploy: false,
        },
        hostScanner: {
          deploy: false,
        },
        runtimeScanner: {
          deploy: false,
        }
      },
    },
  }
  nodeAnalyzerConfigs = setNodeAnalyzerConfigsRuntimeScanner(params, nodeAnalyzerConfigs)

  // if (params.regionInput === "custom") {
  //   nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.sslVerifyCertificate = false
  // }

  // if (params.hostScannerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsHostScanner(params, nodeAnalyzerConfigs)
  // }

  // if (params.runtimeScannerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsRuntimeScanner(params, nodeAnalyzerConfigs)
  // }

  // if (params.imageAnalyzerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsImageAnalyzer(params, nodeAnalyzerConfigs)
  // }

  // if (params.hostAnalyzerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsHostAnalyzer(params, nodeAnalyzerConfigs)
  // }

  // if (params.benchmarkRunnerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsBenchmarkRunner(params, nodeAnalyzerConfigs)
  // }

  // if (params.kspmCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigsKSPMAnalyzer(params, nodeAnalyzerConfigs)
  // }

  if (params.registryCheckbox.checked) {
    nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.runtimeScanner.image = {
      repository: params.registryInputs[0].value + "/" + params.registryInputs[4].value,
      tag: params.registryInputs[5].value,
    }
    if (params.registryInputs[1].value != "") {
      nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.pullSecrets = params.registryInputs[1].value;
    }
  }
  else {
    nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.runtimeScanner.image = {
      tag: params.runtimeScannerTagsSelect.value,
    }
  }

  // if (params.priorityCheckbox.checked) {
  //   nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.priorityClassName = params.priorityInput
  // }
  

  return nodeAnalyzerConfigs
}

function setNodeAnalyzerConfigsHostScanner(params, nodeAnalyzerConfigs) {
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.hostScanner = {
    deploy: true,
  }
  return nodeAnalyzerConfigs
}

function convertBytesToGigabytes(bytes) {
  return bytes / (1024 * 1024 * 1024);
}

function setNodeAnalyzerConfigsRuntimeScanner(params, nodeAnalyzerConfigs) {
  // need to param imagesize allowed and resource requests/limits
  let maxImageSize = '2147483648'
  let ephemeralStorageRequestGigabytes = '3Gi'
  let ephemeralStorageLimitGigabytes = '6Gi'
  let memoryLimitGigabytes = '4Gi'
  if (params.imageSizeInput != null && parseInt(params.imageSizeInput.value) > parseInt(maxImageSize)) {
    maxImageSize = params.imageSizeInput.value
    let ephemeralStorageRequestBytes = 1.5 * maxImageSize;
    ephemeralStorageRequestGigabytes = Math.ceil(convertBytesToGigabytes(ephemeralStorageRequestBytes)) +'Gi';
    let ephemeralStorageLimitBytes = 3 * maxImageSize;
    ephemeralStorageLimitGigabytes = Math.ceil(convertBytesToGigabytes(ephemeralStorageLimitBytes)) + 'Gi';
    let memoryLimitBytes = 2 * maxImageSize;
    memoryLimitGigabytes = Math.ceil(convertBytesToGigabytes(memoryLimitBytes)) + 'Gi';
  }
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.runtimeScanner = {
    deploy: true,
    settings: {
      eveEnabled: false,
      maxImageSizeAllowed: maxImageSize,
      maxFileSizeAllowed: '500000000',
    },
    eveConnector: {
      deploy: false,
    },
    resources: {
      requests: {
        'ephemeral-storage': ephemeralStorageRequestGigabytes,
      },
      limits: {
        cpu: '1000m',
        memory: memoryLimitGigabytes,
        'ephemeral-storage': ephemeralStorageLimitGigabytes,
      },
    },
  }

  return nodeAnalyzerConfigs
}

function setNodeAnalyzerConfigsImageAnalyzer(params, nodeAnalyzerConfigs) {
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.imageAnalyzer = {
    deploy: true,
  }
  return nodeAnalyzerConfigs
}

function setNodeAnalyzerConfigsHostAnalyzer(params, nodeAnalyzerConfigs) {
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.hostAnalyzer = {
    deploy: true,
  }
  return nodeAnalyzerConfigs
}

function setNodeAnalyzerConfigsBenchmarkRunner(params, nodeAnalyzerConfigs) {
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.benchmarkRunner = {
    deploy: true,
  }
  return nodeAnalyzerConfigs
}

function setNodeAnalyzerConfigsKSPMAnalyzer(params, nodeAnalyzerConfigs) {
  nodeAnalyzerConfigs.nodeAnalyzer.nodeAnalyzer.kspmAnalyzer = {
    resources: {
      requests: {
        cpu: '150m',
        memory: '187Mi'
      },
      limits: {
        cpu: '500m',
        memory: '1536Mi'
      }
    }
  }
  return nodeAnalyzerConfigs
}

function setAdmissionControllerConfigs(params) {
  let admissionControllerConfigs = {
    admissionController: {
      enabled: params.admissionControllerCheckbox.checked,
      scanner: {
        enabled: false
      },
      sysdig: {
        url: 'https://us2.app.sysdig.com' //need to put correct url here
      },
      webhook: {
        autoscaling: {
          minReplicas: 1
        },
        resources: {
          requests: {
            cpu: '245m',
            memory: '192Mi'
          },
          limits: {
            cpu: '250m',
            memory: '384Mi'
          }
        }
      }
    }
  }

  return admissionControllerConfigs
}

function setKSPMCollectorConfigs(params) {
  let kspmCollectorConfigs = {
    kspmCollector: {
      resources: {
        requests: {
          cpu: '150m',
          memory: '187Mi'
        },
        limits: {
          cpu: '500m',
          memory: '1536Mi'
        }
      }
    }
  }

  if (params.priorityCheckbox.checked){
    kspmCollectorConfigs.kspmCollector.priorityClassName = params.priorityInput
  }

  return kspmCollectorConfigs
}

function setRapidResponseConfigs(params) {
  let rapidResponseConfigs = {
    rapidResponse: {
      enabled: params.rapidResponseCheckbox.checked,
      resources: {
        limits: {
          cpu: '500m',
          memory: '500Mi'
        },
        requests: {
          cpu: '250m',
          memory: '250Mi'
        }
      }
    }
  }
  return rapidResponseConfigs
}

function createTagLine() {
  const tagWrapper = document.createElement('div');
  tagWrapper.classList.add('tag-wrapper');

  const keyInput = document.createElement('input');
  keyInput.type = 'text';
  keyInput.classList.add('tag-key');
  keyInput.placeholder = 'Tag';
  keyInput.oninput = updateOutput;

  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.classList.add('tag-value');
  valueInput.placeholder = 'Value';

  valueInput.oninput = updateOutput;
  const removeButton = document.createElement('button');
  removeButton.textContent = 'Remove';
  removeButton.className = "secondary"
  removeButton.onclick = function () {
    tagWrapper.remove();
    updateOutput()
  }

  tagWrapper.append(keyInput, ":", valueInput, removeButton);

  return tagWrapper
}

function addTagLine() {
  const tagLines = document.getElementById('tagLines');
  tagLines.appendChild(createTagLine());
}

// Needed to trigger yaml generation after all elements have loaded.
document.addEventListener('DOMContentLoaded', function() {
  updateOutput()
}, false);


function updateOutput() {
  let helmCommandLineInstall = generateHelmCommandLineInstall()
  let yaml = generateYaml()
  let installCommand = generateInstallCommand()
  let installCommandForStaticValues = generateInstallCommandForStaticValues()

  const helmCommandLineInstallOutputDiv = document.getElementById('helm-commands');
  helmCommandLineInstallOutputDiv.innerHTML = helmCommandLineInstall;

  const valuesOutputDiv = document.getElementById('values-yaml');
  valuesOutputDiv.innerHTML = yaml;

  const installCommandOutputDiv = document.getElementById('install-command');
  installCommandOutputDiv.innerHTML = installCommand;

  const installCommandForStaticValuesOutputDiv = document.getElementById('install-command-static-values');
  installCommandForStaticValuesOutputDiv.innerHTML = installCommandForStaticValues;
}

function generateYaml() {
  // Retrieve user inputs
  // const params = {
  //   namespaceInput: document.querySelector('#namespaceInput input').value,
  //   accessKeyInput: document.querySelector('#accessKeyInput input').value,
  //   clusterNameInput: document.querySelector('#clusterNameInput input').value,
  //   agentProfileInput: document.getElementById('profileSelect').value,
  //   clusterTags: {},
  //   proxyCheckbox: document.getElementById('proxyCheckbox'),
  //   proxyInputs: document.getElementById('proxyInput').getElementsByTagName('input'),
  //   registryCheckbox: document.getElementById('registryCheckbox'),
  //   registryInputs: document.getElementById('registryInput').getElementsByTagName('input'),
  //   priorityCheckbox: document.getElementById('priorityCheckbox'),
  //   priorityInput: document.querySelector('#priorityInput input').value,
  //   nodeAnalyzerCheckbox: document.getElementById('nodeAnalyzerCheckbox'),
  //   admissionControllerCheckbox: document.getElementById('admissionControllerCheckbox'),
  //   kspmCheckbox: document.getElementById('kspmCheckbox'),
  //   rapidResponseCheckbox: document.getElementById('rapidResponseCheckbox'),
  //   nodeAnalyzerCheckbox: document.getElementById('nodeAnalyzerCheckbox'),
  //   hostScannerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[0],
  //   runtimeScannerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[1],
  //   imageAnalyzerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[2],
  //   hostAnalyzerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[3],
  //   benchmarkRunnerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[4],
  //   imageSizeInput: document.querySelector('#imageSizeInput input'),
  //   agentMemoryInput: document.querySelector('#agentMemoryInput input'),
  //   regionInput: '',
  //   customCollectorUrl: '',
  //   customCollectorPort: '',
  // }

  // const regionSelect = document.getElementById('regionSelect');
  // if (regionSelect.value === 'custom') {
  //   params.regionInput = "custom";
  //   params.customCollectorUrl = document.getElementById('customCollectorUrl').value;
  //   params.customCollectorPort = document.getElementById('customCollectorPort').value;
  // } else {
  //   params.regionInput = regionSelect.value;
  // }

  // // Validate required inputs
  // if (!params.namespaceInput || !params.accessKeyInput || !params.regionInput || !params.clusterNameInput) {
  //   return 'Please fill in all required fields.';
  // }

  // const clusterTagElements = document.getElementById('tagLines').children;
  // for (let i = 0; i < clusterTagElements.length; i++) {
  //   const key = clusterTagElements[i].getElementsByTagName('input')[0].value;
  //   const value = clusterTagElements[i].getElementsByTagName('input')[1].value;

  //   if (key && value) {
  //     params.clusterTags[key] = value;
  //   }
  // }

  params = generateUserInputParamObject()

  const globalConfigs = setGlobalConfigs(params)
  const agentConfigs = setAgentConfigs(params)
  let nodeAnalyzerConfigs = "";
  let rapidResponseConfigs = "";
  let kspmCollectorConfigs = "";
  let admissionControllerConfigs = "";
  // if (nodeAnalyzerCheckbox.checked) {
  //   nodeAnalyzerConfigs = setNodeAnalyzerConfigs(params)
  // }
  nodeAnalyzerConfigs = setNodeAnalyzerConfigs(params)
  // if (rapidResponseCheckbox.checked) {
  //   rapidResponseConfigs = setRapidResponseConfigs(params)
  // }
  // if (kspmCheckbox.checked) {
  //   kspmCollectorConfigs = setKSPMCollectorConfigs(params)
  // }

  // if (admissionControllerCheckbox.checked) {
  //   admissionControllerConfigs = setAdmissionControllerConfigs(params)
  // }

  const data = {
    ...globalConfigs,
    ...agentConfigs,
    ...nodeAnalyzerConfigs,
    // ...rapidResponseConfigs,
    // ...kspmCollectorConfigs,
    // ...admissionControllerConfigs
  };

  return jsyaml.dump(data);
}

function generateUserInputParamObject() {
  const params = {
    businessUnit: document.getElementById('businessUnit').value.toLowerCase(),
    environment: document.getElementById('environmentSelect').value.toLowerCase(),
    platform: document.getElementById('platformSelect').value.toLowerCase(),
    vsadId: document.getElementById('vsad').value.toLowerCase(),
    vastId: document.getElementById('vast').value.toLowerCase(),
    agentTagsSelect: document.getElementById('agentTags'),
    runtimeScannerTagsSelect: document.getElementById('runtimeScannerTags'),
    namespaceInput: document.querySelector('#namespaceInput input').value,
    accessKeyInput: document.querySelector('#accessKeyInput input').value,
    // clusterNameInput: document.querySelector('#clusterNameInput input').value,
    // agentProfileInput: document.getElementById('profileSelect').value,
    // clusterTags: {},
    proxyCheckbox: document.getElementById('proxyCheckbox'),
    proxyInputs: document.getElementById('proxyInput').getElementsByTagName('input'),
    registryCheckbox: document.getElementById('registryCheckbox'),
    registryInputs: document.getElementById('registryInput').getElementsByTagName('input'),
    // priorityCheckbox: document.getElementById('priorityCheckbox'),
    // priorityInput: document.querySelector('#priorityInput input').value,
    // nodeAnalyzerCheckbox: document.getElementById('nodeAnalyzerCheckbox'),
    // admissionControllerCheckbox: document.getElementById('admissionControllerCheckbox'),
    // kspmCheckbox: document.getElementById('kspmCheckbox'),
    // rapidResponseCheckbox: document.getElementById('rapidResponseCheckbox'),
    // nodeAnalyzerCheckbox: document.getElementById('nodeAnalyzerCheckbox'),
    // hostScannerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[0],
    // runtimeScannerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[1],
    // imageAnalyzerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[2],
    // hostAnalyzerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[3],
    // benchmarkRunnerCheckbox: document.getElementById('nodeAnalyzerInput').getElementsByTagName('input')[4],
    imageSizeInput: document.querySelector('#imageSizeInput input'),
    // agentMemoryInput: document.querySelector('#agentMemoryInput input'),
    // regionInput: '',
    customCollectorUrl: '',
    customCollectorPort: '',
  }

  // const regionSelect = document.getElementById('regionSelect');
  // if (regionSelect.value === 'custom') {
  //   params.regionInput = "custom";
  //   params.customCollectorUrl = document.getElementById('customCollectorUrl').value;
  //   params.customCollectorPort = document.getElementById('customCollectorPort').value;
  // } else {
  //   params.regionInput = regionSelect.value;
  // }

  // Validate required inputs
  if (!params.namespaceInput || !params.accessKeyInput) {
    return 'Please fill in all required fields.';
  }

  // const clusterTagElements = document.getElementById('tagLines').children;
  // for (let i = 0; i < clusterTagElements.length; i++) {
  //   const key = clusterTagElements[i].getElementsByTagName('input')[0].value;
  //   const value = clusterTagElements[i].getElementsByTagName('input')[1].value;

  //   if (key && value) {
  //     params.clusterTags[key] = value;
  //   }
  // }

  return params
}

function generateHelmCommandLineInstall() {
  params = generateUserInputParamObject()
  let helmCommands = "helm upgrade -i --create-namespace sysdig-agent \\"
  helmCommands += "<br>&nbsp;&nbsp; --namespace " + params.namespaceInput + " \\";
  helmCommands += setHelmCommandGlobalConfigs(params)
  helmCommands += setHelmCommandAgentConfigs(params)
  helmCommands += "<br>&nbsp;&nbsp; -f static-configs.yaml \\";
  helmCommands += "<br>sysdig/sysdig-deploy";
  return helmCommands
}

function generateInstallCommandForStaticValues() {
  let namespace = document.querySelector('#namespaceInput input').value;

  if (!namespace) {
    return 'Please fill in all required fields.';
  }

  return `<strong>REVIEW PRE-REQ DOCS <a target="_blank"
        href="https://github.com/alexwang19/alexwang19.github.io/blob/main/docs/installation_docs.md">HERE</a> </strong><br>Install Commands<br>Copy the above content and save to a file for future reference. <br><br> Click Download button to download static-configs.yaml file. 
  <br>This contains standard configs for all Sysdig deployments. <br>
  DO NOT edit this file.<br><br>Run<br>helm repo add sysdig https://charts.sysdig.com --force-update <br><br> Then run commands copied from above.`
}

function generateInstallCommand() {
  let namespace = document.querySelector('#namespaceInput input').value;

  if (!namespace) {
    return 'Please fill in all required fields.';
  }

  return `<strong>REVIEW PRE-REQ DOCS <a target="_blank"
        href="https://github.com/alexwang19/alexwang19.github.io/blob/main/docs/installation_docs.md">HERE</a></strong><br>Install Commands<br>helm repo add sysdig https://charts.sysdig.com --force-update <br><br> helm upgrade -i --force sysdig-agent --namespace ${namespace} --create-namespace -f values.yaml sysdig/sysdig-deploy`
}

function downloadYaml() {
  const content = generateYaml();
  // Create a Blob with the YAML content
  const blob = new Blob([content], { type: 'text/yaml' });

  // Create a temporary <a> element to trigger the download
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'values.yaml';
  link.click();
}

function showTab(tabId) {
  var tabs = document.getElementsByClassName("tab-content");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].style.display = "none";
  }
  document.getElementById(tabId).style.display = "block";
  var tabButtons = document.getElementsByClassName("tab-button");
  for (var i = 0; i < tabButtons.length; i++) {
    tabButtons[i].classList.remove("active-tab");
  }
  const completeValues = document.getElementById('static-values');
  const staticValues = document.getElementById('complete-values');
  if (tabId == "values-yaml") {
    completeValues.classList.add('hidden');
    staticValues.classList.remove('hidden');
  }
  else if (tabId == "helm-commands") {
    staticValues.classList.add('hidden');
    completeValues.classList.remove('hidden');
  }
  document.querySelector('[onclick="showTab(\'' + tabId + '\')"]').classList.add("active-tab");
}

// function autoPopulateClusterName(params) {
//   // const businessUnit = document.getElementById('businessUnit').value.toLowerCase();
//   // const environment = document.getElementById('environmentSelect').value.toLowerCase();
//   // const platform = document.getElementById('platformSelect').value.toLowerCase();
//   // const vsadId = document.getElementById('vsad').value.toLowerCase();
//   // const vastId = document.getElementById('vast').value.toLowerCase();

//   // const clusterNameInput = document.getElementById('clusterName');
//   const nameParts = [];

//   if (params.businessUnit) {
//     nameParts.push(params.businessUnit);
//   }
//   if (params.platform) {
//     nameParts.push(params.platform);
//   }
//   if (params.environment) {
//     nameParts.push(params.environment);
//   }
//   if (params.vastId) {
//     nameParts.push(params.vastId);
//   }
//   if (params.vsadId) {
//     nameParts.push(params.vsadId);
//   }


//   const clusterName = nameParts.join('-');
//   params.clusterNameInput = clusterName;
//   // updateOutput()
//   return params
// }

// // // Add input event listeners to related input fields
// const inputFields = document.querySelectorAll('#businessUnit, #environment, #platform, #vsad, #vast');
// let params = generateUserInputParamObject()
// inputFields.forEach(function (inputField) {
//   inputField.addEventListener('input', autoPopulateClusterName(params));
// });

// Function to fetch the tags from the Quay.io repository and populate the dropdown
function populateTagOptions() {
  const dropdown = document.getElementById('agentTags');

  fetch('https://quay.io/api/v1/repository/sysdig/agent/tag/', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  })
    .then(response => response.json())
    .then(data => {
      const tags = data.tags
        .filter(tag => isValidVersion(tag.name))
        .map(tag => formatTagVersion(tag.name));
      const uniqueTags = Array.from(new Set(tags));
      const lastFiveUniqueTags = uniqueTags.slice(0, 3);
      lastFiveUniqueTags.forEach(tag => {
        const option = document.createElement('option');
        option.value = tag;
        option.textContent = tag;
        dropdown.appendChild(option);
      });
    })
    .catch(error => {
      console.error('Error fetching tags:', error);
    });
}

// Function to format the tag version in "1.14.1" format
function formatTagVersion(tag) {
  const versionParts = tag.split('-');
  return versionParts[0];
}

// Call the populateTagOptions() function to populate the dropdown on page load
window.addEventListener('DOMContentLoaded', populateTagOptions);


// Function to fetch the tags from the Quay.io repository and populate the dropdown
function populateRuntimeScannerTagOptions() {
  const dropdown = document.getElementById('runtimeScannerTags');

  fetch('https://quay.io/api/v1/repository/sysdig/vuln-runtime-scanner/tag/', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  })
    .then(response => response.json())
    .then(data => {
      const tags = data.tags
        .filter(tag => isValidVersion(tag.name))
        .map(tag => formatTagVersion(tag.name));
      const uniqueTags = Array.from(new Set(tags));
      const lastFiveUniqueTags = uniqueTags.slice(0, 5);
      lastFiveUniqueTags.forEach(tag => {
        const option = document.createElement('option');
        option.value = tag;
        option.textContent = tag;
        dropdown.appendChild(option);
      });
    })
    .catch(error => {
      console.error('Error fetching tags:', error);
    });
}

function isValidVersion(version) {
  return /^(\d+|\d+\.\d+)$/.test(version) || /^\d+\.\d+\.\d+$/.test(version);
  // return /^\d+\.\d+\.\d+$/.test(version);
}

// Comparison function for version strings
function compareVersions(a, b) {
  console.log("OUtside tag: ", a);
  if (isValidVersion(a)) {
    console.log("Tag: ", a);
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);

    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
      const partA = partsA[i] || 0;
      const partB = partsB[i] || 0;

      if (partA < partB) {
        return -1;
      }
      if (partA > partB) {
        return 1;
      }
    }
  }

  return -1;
}

// Function to format the tag version in "1.5.1" format
// function formatRuntimeScannerTagVersion(tag) {
//   const versionParts = tag.split('-');
//   return versionParts[0];
// }

window.addEventListener('DOMContentLoaded', populateRuntimeScannerTagOptions);

let importedYamlData = ""
function importYamlFile() {
  fetch('files/static-configs.yaml')
    .then(response => response.text())
    .then(yamlContent => {
      // Parse the YAML content
      importedYamlData = yamlContent;
    })
    .catch(error => {
      console.error('Error importing YAML file:', error);
    });
}

// Call the importYamlFile function to import the YAML file
importYamlFile();


// Function to download the imported YAML file
function downloadStaticYamlFile() {
  if (importedYamlData) {

    // Create a Blob with the YAML content
    const blob = new Blob([importedYamlData], { type: 'text/yaml' });
    // outputDiv.innerHTML = outputText;
    // Create a temporary <a> element to trigger the download
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'static-helm-values.yaml';
    link.click();
  } else {
    console.error('No imported YAML data available.');
  }
}
