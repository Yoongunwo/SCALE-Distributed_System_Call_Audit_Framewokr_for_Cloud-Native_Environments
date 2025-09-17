# SCALE-Distributed-System-Call-Audit-Framework-for-Cloud-Native-Environments

This repository provides **SCALE**, a system call event collection framework for cloud-native workloads running in Kubernetes. SCALE adopts the sidecar pattern, where a monitoring container is deployed alongside the application container. This design enables real-time collection of system calls from application containers without granting excessive privileges to the monitoring component.

# Overview

<div align="center">
    <img width="600" height="340" alt="Image" src="https://github.com/user-attachments/assets/f5d87a38-d506-4cc3-b5c9-eb1dec215149" />
</div>

In the user space, the components include the Init Manager, BPF Map Manager, BPF File Descriptor, and Monitoring Container. The Init Manager and BPF Map Manager identify required environmental information and distribute configurations, ensuring that each Monitoring Container can collect system call events effectively. Each Monitoring Container runs as a sidecar alongside its corresponding application container within the same network namespace. It creates probes for each system call that process event data within the kernel and collects the resulting outputs.

In the kernel space, SCALE consists of Container-Specific Probes, Invocation Map, and Syscall Dispatchers. The Syscall Dispatchers hooks into the system call path and, upon each system call, identifies the application container that issued the call and triggers the corresponding probe of its Monitoring container. Once activated, the probe extracts and preprocesses system call metadata before placing it into a shared buffer accessible to the collector.

# How to use
**SCALE** can be executed as follows:

1. Run `make` inside the `/SCALE/Control` directory  
2. Launch the SCALE Manager by executing `/SCALE/build/main_controller`  
3. On the Kubernetes master node, deploy `/SCALE/pod.yaml` to create a Pod containing both the application and monitoring containers  

# Evaluation
The detailed evaluation methodology and results can be found in the paper (currently under review). The main evaluation involves a performance comparison with existing system call collection tools, Tetragon and Tracee, and the experimental results are shown below.

<p align="center">
  <img width="300" height="150" alt="Image1" src="https://github.com/user-attachments/assets/f3b6db4c-6e4d-4c13-95b9-d0ece8418eb6" />
  <img width="300" height="150" alt="Image2" src="https://github.com/user-attachments/assets/d15c0cce-91a0-4dc5-af5a-bb4211708df3" />
  <img width="300" height="150" alt="Image3" src="https://github.com/user-attachments/assets/35ec8371-2ae6-4c92-ae86-f226a85c4ea4" />
</p>