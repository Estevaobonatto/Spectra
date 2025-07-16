# -*- coding: utf-8 -*-
"""
Enhanced GPU Manager for Spectra Hash Cracking
Comprehensive GPU detection and management for NVIDIA, AMD, and Intel devices
"""

import os
import time
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

from ..core.console import console
from ..core.logger import get_logger

# GPU Framework imports with fallbacks
try:
    import cupy as cp
    import cupy.cuda.runtime as runtime
    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False
    cp = None

try:
    import pycuda.driver as cuda
    import pycuda.autoinit
    PYCUDA_AVAILABLE = True
except ImportError:
    PYCUDA_AVAILABLE = False
    cuda = None

try:
    import pyopencl as cl
    PYOPENCL_AVAILABLE = True
except ImportError:
    PYOPENCL_AVAILABLE = False
    cl = None

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = get_logger(__name__)


class GPUFramework(Enum):
    """Supported GPU frameworks."""
    CUDA = "cuda"
    CUPY = "cupy"
    OPENCL = "opencl"
    CPU_FALLBACK = "cpu"


class GPUVendor(Enum):
    """GPU vendors."""
    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"
    UNKNOWN = "unknown"


@dataclass
class GPUDevice:
    """Complete GPU device specification."""
    device_id: int
    name: str
    vendor: GPUVendor
    framework: GPUFramework
    memory_total: int  # bytes
    memory_available: int  # bytes
    compute_units: int
    max_workgroup_size: int
    compute_capability: Optional[Tuple[int, int]] = None
    clock_rate: Optional[int] = None  # MHz
    memory_clock_rate: Optional[int] = None  # MHz
    memory_bus_width: Optional[int] = None  # bits
    l2_cache_size: Optional[int] = None  # bytes
    max_threads_per_block: Optional[int] = None
    max_shared_memory_per_block: Optional[int] = None
    warp_size: Optional[int] = None
    performance_score: float = 0.0
    temperature: Optional[float] = None  # Celsius
    power_usage: Optional[float] = None  # Watts
    utilization: float = 0.0  # percentage
    driver_version: Optional[str] = None
    is_integrated: bool = False


@dataclass
class GPUHealthStatus:
    """Real-time GPU health monitoring."""
    device_id: int
    temperature: float
    memory_used: int
    memory_total: int
    utilization: float
    power_usage: float
    clock_rate: int
    memory_clock_rate: int
    fan_speed: Optional[int] = None
    thermal_throttling: bool = False
    error_count: int = 0
    last_update: float = 0.0


@dataclass
class GPUMemoryBlock:
    """GPU memory management tracking."""
    device_id: int
    address: int
    size: int
    allocated_time: float
    purpose: str
    is_active: bool = True


@dataclass
class GPUPerformanceMetrics:
    """Performance data collection."""
    device_id: int
    hashes_per_second: float
    memory_throughput: float  # GB/s
    compute_utilization: float  # percentage
    memory_utilization: float  # percentage
    efficiency_score: float
    thermal_throttling_time: float  # seconds
    error_rate: float  # percentage
    batch_processing_time: float  # seconds
    power_efficiency: float  # hashes per watt
    timestamp: float


class EnhancedGPUManager:
    """Enhanced GPU detection and management system."""
    
    def __init__(self):
        self.gpu_devices: List[GPUDevice] = []
        self.active_contexts: Dict[int, Any] = {}
        self.memory_pools: Dict[int, List[GPUMemoryBlock]] = {}
        self.performance_profiles: Dict[int, GPUPerformanceMetrics] = {}
        self.health_status: Dict[int, GPUHealthStatus] = {}
        
        # Detection results
        self.cuda_devices: List[GPUDevice] = []
        self.opencl_devices: List[GPUDevice] = []
        self.integrated_devices: List[GPUDevice] = []
        
        # Performance tracking
        self.capability_scores: Dict[int, float] = {}
        self.benchmark_results: Dict[int, Dict[str, float]] = {}
        
        logger.info("Enhanced GPU Manager initialized")
        
    def detect_all_gpus(self) -> List[GPUDevice]:
        """
        Comprehensive GPU detection for all supported frameworks.
        
        Returns:
            List[GPUDevice]: All detected GPU devices
        """
        console.print("[bold blue][*] Starting comprehensive GPU detection...[/bold blue]")
        
        self.gpu_devices.clear()
        
        # Detect NVIDIA GPUs via CUDA
        cuda_devices = self._detect_cuda_devices()
        self.cuda_devices = cuda_devices
        self.gpu_devices.extend(cuda_devices)
        
        # Detect GPUs via CuPy (alternative NVIDIA detection)
        if not cuda_devices:  # Only if CUDA detection failed
            cupy_devices = self._detect_cupy_devices()
            self.gpu_devices.extend(cupy_devices)
        
        # Detect AMD/Intel GPUs via OpenCL
        opencl_devices = self._detect_opencl_devices()
        self.opencl_devices = opencl_devices
        self.gpu_devices.extend(opencl_devices)
        
        # Detect integrated graphics
        integrated_devices = self._detect_integrated_graphics()
        self.integrated_devices = integrated_devices
        self.gpu_devices.extend(integrated_devices)
        
        # Calculate performance scores
        self._calculate_performance_scores()
        
        # Sort by performance score (best first)
        self.gpu_devices.sort(key=lambda x: x.performance_score, reverse=True)
        
        # Display detection results
        self._display_detection_results()
        
        return self.gpu_devices
    
    def _detect_cuda_devices(self) -> List[GPUDevice]:
        """Detect NVIDIA GPUs via CUDA with detailed specifications."""
        devices = []
        
        if not PYCUDA_AVAILABLE:
            logger.debug("PyCUDA not available for CUDA detection")
            return devices
        
        try:
            cuda.init()
            device_count = cuda.Device.count()
            
            console.print(f"[green][+] Found {device_count} CUDA device(s)[/green]")
            
            for i in range(device_count):
                device = cuda.Device(i)
                attrs = device.get_attributes()
                
                # Get detailed device information
                gpu_device = GPUDevice(
                    device_id=i,
                    name=device.name(),
                    vendor=GPUVendor.NVIDIA,
                    framework=GPUFramework.CUDA,
                    memory_total=device.total_memory(),
                    memory_available=device.total_memory(),  # Will be updated dynamically
                    compute_units=attrs.get(cuda.device_attribute.MULTIPROCESSOR_COUNT, 0),
                    max_workgroup_size=attrs.get(cuda.device_attribute.MAX_THREADS_PER_BLOCK, 1024),
                    compute_capability=device.compute_capability(),
                    clock_rate=attrs.get(cuda.device_attribute.CLOCK_RATE, 0) // 1000,  # Convert to MHz
                    memory_clock_rate=attrs.get(cuda.device_attribute.MEMORY_CLOCK_RATE, 0) // 1000,
                    memory_bus_width=attrs.get(cuda.device_attribute.GLOBAL_MEMORY_BUS_WIDTH, 0),
                    l2_cache_size=attrs.get(cuda.device_attribute.L2_CACHE_SIZE, 0),
                    max_threads_per_block=attrs.get(cuda.device_attribute.MAX_THREADS_PER_BLOCK, 1024),
                    max_shared_memory_per_block=attrs.get(cuda.device_attribute.MAX_SHARED_MEMORY_PER_BLOCK, 0),
                    warp_size=attrs.get(cuda.device_attribute.WARP_SIZE, 32),
                    driver_version=self._get_cuda_driver_version()
                )
                
                devices.append(gpu_device)
                
                console.print(f"  [bold]CUDA Device {i}:[/bold] {gpu_device.name}")
                console.print(f"    Memory: {gpu_device.memory_total / (1024**3):.1f} GB")
                console.print(f"    Compute Units: {gpu_device.compute_units}")
                console.print(f"    Compute Capability: {gpu_device.compute_capability[0]}.{gpu_device.compute_capability[1]}")
                console.print(f"    Clock Rate: {gpu_device.clock_rate} MHz")
                
        except Exception as e:
            logger.error(f"CUDA detection failed: {e}")
            console.print(f"[red][!] CUDA detection failed: {e}[/red]")
        
        return devices
    
    def _detect_cupy_devices(self) -> List[GPUDevice]:
        """Detect NVIDIA GPUs via CuPy as fallback."""
        devices = []
        
        if not CUPY_AVAILABLE:
            logger.debug("CuPy not available for GPU detection")
            return devices
        
        try:
            device_count = cp.cuda.runtime.getDeviceCount()
            
            console.print(f"[green][+] Found {device_count} CuPy device(s)[/green]")
            
            for i in range(device_count):
                with cp.cuda.Device(i):
                    props = cp.cuda.runtime.getDeviceProperties(i)
                    
                    gpu_device = GPUDevice(
                        device_id=i,
                        name=props['name'].decode() if isinstance(props['name'], bytes) else str(props['name']),
                        vendor=GPUVendor.NVIDIA,
                        framework=GPUFramework.CUPY,
                        memory_total=props['totalGlobalMem'],
                        memory_available=props['totalGlobalMem'],
                        compute_units=props['multiProcessorCount'],
                        max_workgroup_size=props['maxThreadsPerBlock'],
                        compute_capability=(props['major'], props['minor']),
                        clock_rate=props.get('clockRate', 0) // 1000,
                        memory_clock_rate=props.get('memoryClockRate', 0) // 1000,
                        memory_bus_width=props.get('memoryBusWidth', 0),
                        l2_cache_size=props.get('l2CacheSize', 0),
                        max_threads_per_block=props['maxThreadsPerBlock'],
                        max_shared_memory_per_block=props.get('sharedMemPerBlock', 0),
                        warp_size=props.get('warpSize', 32)
                    )
                    
                    devices.append(gpu_device)
                    
                    console.print(f"  [bold]CuPy Device {i}:[/bold] {gpu_device.name}")
                    console.print(f"    Memory: {gpu_device.memory_total / (1024**3):.1f} GB")
                    console.print(f"    Compute Units: {gpu_device.compute_units}")
                    
        except Exception as e:
            logger.error(f"CuPy detection failed: {e}")
            console.print(f"[red][!] CuPy detection failed: {e}[/red]")
        
        return devices  
  
    def _detect_opencl_devices(self) -> List[GPUDevice]:
        """Detect AMD and Intel GPUs via OpenCL with compute unit information."""
        devices = []
        
        if not PYOPENCL_AVAILABLE:
            logger.debug("PyOpenCL not available for GPU detection")
            return devices
        
        try:
            platforms = cl.get_platforms()
            
            for platform_idx, platform in enumerate(platforms):
                platform_name = platform.name.lower()
                
                # Determine vendor from platform name
                if 'nvidia' in platform_name:
                    vendor = GPUVendor.NVIDIA
                elif 'amd' in platform_name or 'advanced micro devices' in platform_name:
                    vendor = GPUVendor.AMD
                elif 'intel' in platform_name:
                    vendor = GPUVendor.INTEL
                else:
                    vendor = GPUVendor.UNKNOWN
                
                # Skip NVIDIA devices if already detected via CUDA
                if vendor == GPUVendor.NVIDIA and self.cuda_devices:
                    continue
                
                try:
                    gpu_devices = platform.get_devices(cl.device_type.GPU)
                    
                    for device_idx, device in enumerate(gpu_devices):
                        # Calculate global device ID
                        global_device_id = len(devices)
                        
                        # Determine if integrated graphics
                        is_integrated = self._is_integrated_gpu(device.name, vendor)
                        
                        gpu_device = GPUDevice(
                            device_id=global_device_id,
                            name=device.name.strip(),
                            vendor=vendor,
                            framework=GPUFramework.OPENCL,
                            memory_total=device.global_mem_size,
                            memory_available=device.global_mem_size,
                            compute_units=device.max_compute_units,
                            max_workgroup_size=device.max_work_group_size,
                            clock_rate=device.max_clock_frequency if hasattr(device, 'max_clock_frequency') else None,
                            l2_cache_size=getattr(device, 'global_mem_cache_size', 0),
                            max_shared_memory_per_block=device.local_mem_size,
                            driver_version=device.driver_version,
                            is_integrated=is_integrated
                        )
                        
                        devices.append(gpu_device)
                        
                        console.print(f"  [bold]OpenCL Device {global_device_id}:[/bold] {gpu_device.name}")
                        console.print(f"    Platform: {platform.name}")
                        console.print(f"    Vendor: {vendor.value.upper()}")
                        console.print(f"    Memory: {gpu_device.memory_total / (1024**3):.1f} GB")
                        console.print(f"    Compute Units: {gpu_device.compute_units}")
                        console.print(f"    Integrated: {is_integrated}")
                        
                except cl.RuntimeError as e:
                    logger.debug(f"No GPU devices found on platform {platform.name}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"OpenCL detection failed: {e}")
            console.print(f"[red][!] OpenCL detection failed: {e}[/red]")
        
        if devices:
            console.print(f"[green][+] Found {len(devices)} OpenCL GPU device(s)[/green]")
        
        return devices
    
    def _detect_integrated_graphics(self) -> List[GPUDevice]:
        """Detect integrated graphics (Intel, AMD APU) with special handling."""
        devices = []
        
        # This would typically require platform-specific detection
        # For now, we'll identify integrated GPUs from the OpenCL detection
        # and add additional detection methods
        
        try:
            # Check for Intel integrated graphics via system information
            if os.name == 'nt':  # Windows
                devices.extend(self._detect_windows_integrated_gpu())
            else:  # Linux/Unix
                devices.extend(self._detect_linux_integrated_gpu())
                
        except Exception as e:
            logger.debug(f"Integrated GPU detection failed: {e}")
        
        return devices
    
    def _detect_windows_integrated_gpu(self) -> List[GPUDevice]:
        """Detect integrated GPUs on Windows via WMI or registry."""
        devices = []
        
        try:
            import subprocess
            
            # Use wmic to get GPU information
            result = subprocess.run([
                'wmic', 'path', 'win32_VideoController', 'get', 
                'Name,AdapterRAM,DriverVersion', '/format:csv'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 4:
                            name = parts[2].strip()
                            memory_str = parts[1].strip()
                            driver_version = parts[3].strip()
                            
                            # Check if it's integrated graphics
                            if self._is_integrated_gpu_name(name):
                                try:
                                    memory = int(memory_str) if memory_str.isdigit() else 1024**3  # 1GB default
                                except:
                                    memory = 1024**3
                                
                                vendor = self._determine_vendor_from_name(name)
                                
                                gpu_device = GPUDevice(
                                    device_id=len(devices),
                                    name=name,
                                    vendor=vendor,
                                    framework=GPUFramework.OPENCL,  # Assume OpenCL support
                                    memory_total=memory,
                                    memory_available=memory,
                                    compute_units=4,  # Estimate for integrated
                                    max_workgroup_size=256,  # Conservative estimate
                                    driver_version=driver_version,
                                    is_integrated=True
                                )
                                
                                devices.append(gpu_device)
                                
        except Exception as e:
            logger.debug(f"Windows integrated GPU detection failed: {e}")
        
        return devices
    
    def _detect_linux_integrated_gpu(self) -> List[GPUDevice]:
        """Detect integrated GPUs on Linux via lspci or /proc."""
        devices = []
        
        try:
            import subprocess
            
            # Use lspci to get GPU information
            result = subprocess.run(['lspci', '-v'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_gpu = None
                
                for line in lines:
                    if 'VGA compatible controller' in line or 'Display controller' in line:
                        # Extract GPU name
                        parts = line.split(': ', 1)
                        if len(parts) > 1:
                            current_gpu = parts[1].strip()
                            
                            if self._is_integrated_gpu_name(current_gpu):
                                vendor = self._determine_vendor_from_name(current_gpu)
                                
                                gpu_device = GPUDevice(
                                    device_id=len(devices),
                                    name=current_gpu,
                                    vendor=vendor,
                                    framework=GPUFramework.OPENCL,
                                    memory_total=1024**3,  # 1GB estimate
                                    memory_available=1024**3,
                                    compute_units=4,  # Estimate
                                    max_workgroup_size=256,
                                    is_integrated=True
                                )
                                
                                devices.append(gpu_device)
                                
        except Exception as e:
            logger.debug(f"Linux integrated GPU detection failed: {e}")
        
        return devices
    
    def _is_integrated_gpu(self, device_name: str, vendor: GPUVendor) -> bool:
        """Determine if a GPU is integrated based on name and vendor."""
        name_lower = device_name.lower()
        
        # Intel integrated graphics patterns
        intel_integrated = [
            'intel(r) hd graphics', 'intel(r) iris', 'intel(r) uhd graphics',
            'intel(r) graphics', 'intel hd', 'intel iris', 'intel uhd'
        ]
        
        # AMD integrated graphics patterns
        amd_integrated = [
            'amd radeon(tm) graphics', 'radeon(tm) graphics', 'vega',
            'apu', 'amd graphics'
        ]
        
        if vendor == GPUVendor.INTEL:
            return any(pattern in name_lower for pattern in intel_integrated)
        elif vendor == GPUVendor.AMD:
            return any(pattern in name_lower for pattern in amd_integrated)
        
        return False
    
    def _is_integrated_gpu_name(self, name: str) -> bool:
        """Check if GPU name indicates integrated graphics."""
        name_lower = name.lower()
        
        integrated_patterns = [
            'intel hd', 'intel iris', 'intel uhd', 'intel graphics',
            'radeon graphics', 'vega', 'apu', 'integrated'
        ]
        
        return any(pattern in name_lower for pattern in integrated_patterns)
    
    def _determine_vendor_from_name(self, name: str) -> GPUVendor:
        """Determine GPU vendor from device name."""
        name_lower = name.lower()
        
        if 'intel' in name_lower:
            return GPUVendor.INTEL
        elif 'amd' in name_lower or 'radeon' in name_lower:
            return GPUVendor.AMD
        elif 'nvidia' in name_lower or 'geforce' in name_lower or 'quadro' in name_lower:
            return GPUVendor.NVIDIA
        else:
            return GPUVendor.UNKNOWN
    
    def _get_cuda_driver_version(self) -> Optional[str]:
        """Get CUDA driver version."""
        try:
            if PYCUDA_AVAILABLE:
                return f"{cuda.get_driver_version()}"
            elif CUPY_AVAILABLE:
                return f"{cp.cuda.runtime.driverGetVersion()}"
        except:
            pass
        return None
    
    def _calculate_performance_scores(self):
        """Calculate performance scores for GPU capability ranking."""
        for device in self.gpu_devices:
            score = 0.0
            
            # Base score from compute units
            score += device.compute_units * 10
            
            # Memory bandwidth contribution
            if device.memory_total:
                score += (device.memory_total / (1024**3)) * 50  # 50 points per GB
            
            # Clock rate contribution
            if device.clock_rate:
                score += device.clock_rate * 0.1  # 0.1 points per MHz
            
            # Framework preference (CUDA > CuPy > OpenCL)
            if device.framework == GPUFramework.CUDA:
                score *= 1.2
            elif device.framework == GPUFramework.CUPY:
                score *= 1.1
            elif device.framework == GPUFramework.OPENCL:
                score *= 1.0
            
            # Vendor preference for hash cracking (NVIDIA > AMD > Intel)
            if device.vendor == GPUVendor.NVIDIA:
                score *= 1.3
            elif device.vendor == GPUVendor.AMD:
                score *= 1.1
            elif device.vendor == GPUVendor.INTEL:
                score *= 0.8
            
            # Penalty for integrated graphics
            if device.is_integrated:
                score *= 0.5
            
            # Compute capability bonus for NVIDIA
            if device.compute_capability:
                major, minor = device.compute_capability
                capability_score = major * 10 + minor
                score += capability_score * 20
            
            device.performance_score = score
            self.capability_scores[device.device_id] = score
    
    def _display_detection_results(self):
        """Display comprehensive GPU detection results."""
        if not self.gpu_devices:
            console.print("[red][!] No GPU devices detected[/red]")
            console.print("[yellow][*] Hash cracking will use CPU-only processing[/yellow]")
            return
        
        console.print(f"\n[bold green][+] GPU Detection Complete: {len(self.gpu_devices)} device(s) found[/bold green]")
        console.print("[bold blue]Performance Ranking (Best to Worst):[/bold blue]")
        
        for i, device in enumerate(self.gpu_devices, 1):
            status_color = "green" if i <= 3 else "yellow"
            
            console.print(f"\n[bold {status_color}]#{i} {device.name}[/bold {status_color}]")
            console.print(f"    Vendor: {device.vendor.value.upper()}")
            console.print(f"    Framework: {device.framework.value.upper()}")
            console.print(f"    Memory: {device.memory_total / (1024**3):.1f} GB")
            console.print(f"    Compute Units: {device.compute_units}")
            console.print(f"    Performance Score: {device.performance_score:.1f}")
            
            if device.compute_capability:
                console.print(f"    Compute Capability: {device.compute_capability[0]}.{device.compute_capability[1]}")
            
            if device.is_integrated:
                console.print(f"    [yellow]Type: Integrated Graphics[/yellow]")
            else:
                console.print(f"    [green]Type: Discrete GPU[/green]")
        
        # Performance summary
        best_device = self.gpu_devices[0]
        estimated_speedup = self._estimate_performance_gain(best_device)
        
        console.print(f"\n[bold cyan]Recommended GPU: {best_device.name}[/bold cyan]")
        console.print(f"[bold cyan]Estimated Performance Gain: {estimated_speedup:.0f}x over CPU[/bold cyan]")
    
    def _estimate_performance_gain(self, device: GPUDevice) -> float:
        """Estimate performance gain over CPU for hash cracking."""
        base_gain = 10.0  # Minimum expected gain
        
        # Scale by compute units
        compute_gain = device.compute_units * 2
        
        # Memory bandwidth contribution
        memory_gain = (device.memory_total / (1024**3)) * 5
        
        # Framework efficiency
        framework_multiplier = {
            GPUFramework.CUDA: 1.5,
            GPUFramework.CUPY: 1.3,
            GPUFramework.OPENCL: 1.0
        }.get(device.framework, 1.0)
        
        # Vendor efficiency for hash algorithms
        vendor_multiplier = {
            GPUVendor.NVIDIA: 1.4,
            GPUVendor.AMD: 1.2,
            GPUVendor.INTEL: 0.8
        }.get(device.vendor, 1.0)
        
        # Integrated graphics penalty
        integrated_penalty = 0.3 if device.is_integrated else 1.0
        
        total_gain = (base_gain + compute_gain + memory_gain) * framework_multiplier * vendor_multiplier * integrated_penalty
        
        return max(total_gain, 5.0)  # Minimum 5x gain
    
    def get_best_device(self) -> Optional[GPUDevice]:
        """Get the best performing GPU device."""
        if not self.gpu_devices:
            return None
        return self.gpu_devices[0]  # Already sorted by performance
    
    def get_devices_by_vendor(self, vendor: GPUVendor) -> List[GPUDevice]:
        """Get all devices from a specific vendor."""
        return [device for device in self.gpu_devices if device.vendor == vendor]
    
    def get_devices_by_framework(self, framework: GPUFramework) -> List[GPUDevice]:
        """Get all devices supporting a specific framework."""
        return [device for device in self.gpu_devices if device.framework == framework]
    
    def is_gpu_available(self) -> bool:
        """Check if any GPU is available for acceleration."""
        return len(self.gpu_devices) > 0
    
    def get_total_gpu_memory(self) -> int:
        """Get total GPU memory across all devices."""
        return sum(device.memory_total for device in self.gpu_devices)
    
    def get_device_by_id(self, device_id: int) -> Optional[GPUDevice]:
        """Get device by ID."""
        for device in self.gpu_devices:
            if device.device_id == device_id:
                return device
        return None
class GPUDeviceSelector:
    """Advanced device selection algorithms based on capabilities."""
    
    def __init__(self, gpu_manager: 'EnhancedGPUManager'):
        self.gpu_manager = gpu_manager
        self.selection_history: List[Dict[str, Any]] = []
        
    def select_optimal_device(self, 
                            algorithm: str = "md5",
                            batch_size: int = 10000,
                            memory_requirement: int = 0,
                            prefer_vendor: Optional[GPUVendor] = None,
                            require_framework: Optional[GPUFramework] = None) -> Optional[GPUDevice]:
        """
        Select optimal GPU device based on specific requirements.
        
        Args:
            algorithm: Hash algorithm to optimize for
            batch_size: Expected batch size
            memory_requirement: Minimum memory requirement in bytes
            prefer_vendor: Preferred GPU vendor
            require_framework: Required framework support
            
        Returns:
            Optimal GPUDevice or None if no suitable device found
        """
        available_devices = self.gpu_manager.gpu_devices.copy()
        
        if not available_devices:
            return None
        
        # Filter by framework requirement
        if require_framework:
            available_devices = [d for d in available_devices if d.framework == require_framework]
        
        # Filter by memory requirement
        if memory_requirement > 0:
            available_devices = [d for d in available_devices if d.memory_available >= memory_requirement]
        
        if not available_devices:
            logger.warning(f"No devices meet requirements: framework={require_framework}, memory={memory_requirement}")
            return None
        
        # Score devices for this specific use case
        scored_devices = []
        for device in available_devices:
            score = self._calculate_algorithm_score(device, algorithm, batch_size)
            
            # Apply vendor preference
            if prefer_vendor and device.vendor == prefer_vendor:
                score *= 1.2
            
            scored_devices.append((device, score))
        
        # Sort by score (highest first)
        scored_devices.sort(key=lambda x: x[1], reverse=True)
        
        selected_device = scored_devices[0][0]
        
        # Record selection for analysis
        self.selection_history.append({
            'timestamp': time.time(),
            'device_id': selected_device.device_id,
            'algorithm': algorithm,
            'batch_size': batch_size,
            'score': scored_devices[0][1],
            'alternatives': len(scored_devices) - 1
        })
        
        return selected_device
    
    def _calculate_algorithm_score(self, device: GPUDevice, algorithm: str, batch_size: int) -> float:
        """Calculate device score for specific algorithm and batch size."""
        base_score = device.performance_score
        
        # Algorithm-specific optimizations
        algorithm_multipliers = {
            'md5': 1.0,
            'sha1': 0.9,
            'sha256': 0.8,
            'sha512': 0.7,
            'ntlm': 1.1,
            'bcrypt': 0.3,  # Not well suited for GPU
            'argon2': 0.2   # Memory-hard, not ideal for GPU
        }
        
        algorithm_score = base_score * algorithm_multipliers.get(algorithm.lower(), 0.8)
        
        # Batch size optimization
        optimal_batch = self._estimate_optimal_batch_size(device)
        batch_efficiency = min(batch_size / optimal_batch, optimal_batch / batch_size) if optimal_batch > 0 else 0.5
        
        # Memory utilization score
        estimated_memory_usage = batch_size * 100  # Rough estimate: 100 bytes per hash
        memory_efficiency = min(estimated_memory_usage / device.memory_available, 1.0) if device.memory_available > 0 else 0.5
        
        final_score = algorithm_score * batch_efficiency * (0.5 + memory_efficiency * 0.5)
        
        return final_score
    
    def _estimate_optimal_batch_size(self, device: GPUDevice) -> int:
        """Estimate optimal batch size for device."""
        # Base on compute units and memory
        compute_factor = device.compute_units * 1000
        memory_factor = device.memory_available // (1024 * 100)  # Assume 100 bytes per item
        
        return min(compute_factor, memory_factor, 100000)  # Cap at 100k
    
    def select_multi_gpu_setup(self, 
                             target_performance: float,
                             algorithm: str = "md5") -> List[GPUDevice]:
        """
        Select multiple GPUs for distributed processing.
        
        Args:
            target_performance: Target performance multiplier
            algorithm: Hash algorithm to optimize for
            
        Returns:
            List of GPUDevice objects for multi-GPU setup
        """
        available_devices = [d for d in self.gpu_manager.gpu_devices if not d.is_integrated]
        
        if not available_devices:
            return []
        
        selected_devices = []
        current_performance = 0.0
        
        # Sort by performance score
        available_devices.sort(key=lambda x: x.performance_score, reverse=True)
        
        for device in available_devices:
            device_performance = self._estimate_device_performance(device, algorithm)
            
            # Check if adding this device is beneficial
            if current_performance == 0 or device_performance > current_performance * 0.3:
                selected_devices.append(device)
                current_performance += device_performance
                
                if current_performance >= target_performance:
                    break
        
        return selected_devices
    
    def _estimate_device_performance(self, device: GPUDevice, algorithm: str) -> float:
        """Estimate device performance for specific algorithm."""
        base_performance = device.compute_units * 1000  # Base hashes per second estimate
        
        # Algorithm complexity factors
        complexity_factors = {
            'md5': 1.0,
            'sha1': 0.8,
            'sha256': 0.6,
            'sha512': 0.4,
            'ntlm': 1.2
        }
        
        return base_performance * complexity_factors.get(algorithm.lower(), 0.7)
    
    def get_selection_statistics(self) -> Dict[str, Any]:
        """Get device selection statistics."""
        if not self.selection_history:
            return {}
        
        device_usage = {}
        algorithm_usage = {}
        
        for selection in self.selection_history:
            device_id = selection['device_id']
            algorithm = selection['algorithm']
            
            device_usage[device_id] = device_usage.get(device_id, 0) + 1
            algorithm_usage[algorithm] = algorithm_usage.get(algorithm, 0) + 1
        
        return {
            'total_selections': len(self.selection_history),
            'device_usage': device_usage,
            'algorithm_usage': algorithm_usage,
            'most_used_device': max(device_usage.items(), key=lambda x: x[1])[0] if device_usage else None,
            'most_used_algorithm': max(algorithm_usage.items(), key=lambda x: x[1])[0] if algorithm_usage else None
        }


class GPUHealthMonitor:
    """Real-time GPU health monitoring and status tracking."""
    
    def __init__(self, gpu_manager: 'EnhancedGPUManager'):
        self.gpu_manager = gpu_manager
        self.monitoring_active = False
        self.monitoring_thread = None
        self.health_history: Dict[int, List[GPUHealthStatus]] = {}
        self.alert_thresholds = {
            'temperature': 85.0,  # Celsius
            'memory_usage': 0.95,  # 95%
            'utilization': 0.98,   # 98%
            'power_usage': 300.0   # Watts
        }
        
    def start_monitoring(self, interval: float = 1.0):
        """Start real-time GPU health monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitoring_thread.start()
        
        logger.info(f"GPU health monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop GPU health monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2.0)
        
        logger.info("GPU health monitoring stopped")
    
    def _monitoring_loop(self, interval: float):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                for device in self.gpu_manager.gpu_devices:
                    health_status = self._collect_health_data(device)
                    
                    if health_status:
                        # Store in manager
                        self.gpu_manager.health_status[device.device_id] = health_status
                        
                        # Store in history
                        if device.device_id not in self.health_history:
                            self.health_history[device.device_id] = []
                        
                        self.health_history[device.device_id].append(health_status)
                        
                        # Keep only last 100 readings
                        if len(self.health_history[device.device_id]) > 100:
                            self.health_history[device.device_id].pop(0)
                        
                        # Check for alerts
                        self._check_health_alerts(health_status)
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(interval)
    
    def _collect_health_data(self, device: GPUDevice) -> Optional[GPUHealthStatus]:
        """Collect health data for a specific device."""
        try:
            if device.framework == GPUFramework.CUDA and PYCUDA_AVAILABLE:
                return self._collect_cuda_health(device)
            elif device.framework == GPUFramework.CUPY and CUPY_AVAILABLE:
                return self._collect_cupy_health(device)
            elif device.framework == GPUFramework.OPENCL and PYOPENCL_AVAILABLE:
                return self._collect_opencl_health(device)
            
        except Exception as e:
            logger.debug(f"Failed to collect health data for device {device.device_id}: {e}")
        
        return None
    
    def _collect_cuda_health(self, device: GPUDevice) -> Optional[GPUHealthStatus]:
        """Collect health data via CUDA."""
        try:
            with cuda.Device(device.device_id):
                # Get memory info
                free_memory, total_memory = cuda.mem_get_info()
                memory_used = total_memory - free_memory
                
                # Basic health status
                health_status = GPUHealthStatus(
                    device_id=device.device_id,
                    temperature=0.0,  # CUDA doesn't provide temperature directly
                    memory_used=memory_used,
                    memory_total=total_memory,
                    utilization=0.0,  # Would need NVML for accurate utilization
                    power_usage=0.0,  # Would need NVML
                    clock_rate=0,     # Would need NVML
                    memory_clock_rate=0,  # Would need NVML
                    last_update=time.time()
                )
                
                return health_status
                
        except Exception as e:
            logger.debug(f"CUDA health collection failed: {e}")
        
        return None
    
    def _collect_cupy_health(self, device: GPUDevice) -> Optional[GPUHealthStatus]:
        """Collect health data via CuPy."""
        try:
            with cp.cuda.Device(device.device_id):
                # Get memory info
                mempool = cp.get_default_memory_pool()
                memory_used = mempool.used_bytes()
                memory_total = device.memory_total
                
                health_status = GPUHealthStatus(
                    device_id=device.device_id,
                    temperature=0.0,
                    memory_used=memory_used,
                    memory_total=memory_total,
                    utilization=0.0,
                    power_usage=0.0,
                    clock_rate=0,
                    memory_clock_rate=0,
                    last_update=time.time()
                )
                
                return health_status
                
        except Exception as e:
            logger.debug(f"CuPy health collection failed: {e}")
        
        return None
    
    def _collect_opencl_health(self, device: GPUDevice) -> Optional[GPUHealthStatus]:
        """Collect health data via OpenCL."""
        # OpenCL has limited health monitoring capabilities
        # This would be a basic implementation
        
        health_status = GPUHealthStatus(
            device_id=device.device_id,
            temperature=0.0,
            memory_used=0,
            memory_total=device.memory_total,
            utilization=0.0,
            power_usage=0.0,
            clock_rate=0,
            memory_clock_rate=0,
            last_update=time.time()
        )
        
        return health_status
    
    def _check_health_alerts(self, health_status: GPUHealthStatus):
        """Check for health alerts and warnings."""
        alerts = []
        
        # Temperature check
        if health_status.temperature > self.alert_thresholds['temperature']:
            alerts.append(f"High temperature: {health_status.temperature:.1f}°C")
        
        # Memory usage check
        memory_usage_ratio = health_status.memory_used / health_status.memory_total
        if memory_usage_ratio > self.alert_thresholds['memory_usage']:
            alerts.append(f"High memory usage: {memory_usage_ratio*100:.1f}%")
        
        # Utilization check
        if health_status.utilization > self.alert_thresholds['utilization']:
            alerts.append(f"High utilization: {health_status.utilization*100:.1f}%")
        
        # Power usage check
        if health_status.power_usage > self.alert_thresholds['power_usage']:
            alerts.append(f"High power usage: {health_status.power_usage:.1f}W")
        
        # Log alerts
        if alerts:
            device_name = self.gpu_manager.get_device_by_id(health_status.device_id)
            device_name = device_name.name if device_name else f"Device {health_status.device_id}"
            
            for alert in alerts:
                logger.warning(f"GPU Health Alert [{device_name}]: {alert}")
    
    def get_health_summary(self) -> Dict[int, Dict[str, Any]]:
        """Get health summary for all monitored devices."""
        summary = {}
        
        for device_id, health_status in self.gpu_manager.health_status.items():
            device = self.gpu_manager.get_device_by_id(device_id)
            
            summary[device_id] = {
                'device_name': device.name if device else f"Device {device_id}",
                'temperature': health_status.temperature,
                'memory_usage_percent': (health_status.memory_used / health_status.memory_total * 100) if health_status.memory_total > 0 else 0,
                'utilization_percent': health_status.utilization * 100,
                'power_usage': health_status.power_usage,
                'thermal_throttling': health_status.thermal_throttling,
                'error_count': health_status.error_count,
                'last_update': health_status.last_update
            }
        
        return summary
    
    def get_health_history(self, device_id: int, hours: int = 1) -> List[GPUHealthStatus]:
        """Get health history for a specific device."""
        if device_id not in self.health_history:
            return []
        
        cutoff_time = time.time() - (hours * 3600)
        return [
            status for status in self.health_history[device_id]
            if status.last_update >= cutoff_time
        ]


# Add the enhanced GPU manager to the existing hash cracker integration
class GPUManagerIntegration:
    """Integration layer for enhanced GPU manager with existing hash cracker."""
    
    @staticmethod
    def create_enhanced_gpu_manager() -> EnhancedGPUManager:
        """Create and initialize enhanced GPU manager."""
        manager = EnhancedGPUManager()
        manager.detect_all_gpus()
        return manager
    
    @staticmethod
    def get_gpu_acceleration_info(manager: EnhancedGPUManager) -> Dict[str, Any]:
        """Get GPU acceleration information for display."""
        if not manager.is_gpu_available():
            return {
                'available': False,
                'message': 'No GPU acceleration available - using CPU only'
            }
        
        best_device = manager.get_best_device()
        estimated_speedup = manager._estimate_performance_gain(best_device)
        
        return {
            'available': True,
            'device_count': len(manager.gpu_devices),
            'best_device': {
                'name': best_device.name,
                'vendor': best_device.vendor.value,
                'framework': best_device.framework.value,
                'memory_gb': best_device.memory_total / (1024**3),
                'compute_units': best_device.compute_units,
                'performance_score': best_device.performance_score
            },
            'estimated_speedup': estimated_speedup,
            'message': f'GPU acceleration available: {estimated_speedup:.0f}x speedup expected'
        }
import thre
ading
from contextlib import contextmanager


class GPUContextManager:
    """GPU context management and initialization for multi-framework support."""
    
    def __init__(self, gpu_manager: 'EnhancedGPUManager'):
        self.gpu_manager = gpu_manager
        self.cuda_contexts: Dict[int, Any] = {}
        self.cupy_contexts: Dict[int, Any] = {}
        self.opencl_contexts: Dict[int, Any] = {}
        self.context_locks: Dict[int, threading.Lock] = {}
        self.initialization_status: Dict[int, bool] = {}
        self.context_recovery_attempts: Dict[int, int] = {}
        self.max_recovery_attempts = 3
        
    def initialize_gpu_contexts(self) -> bool:
        """
        Initialize GPU contexts for all detected devices across frameworks.
        
        Returns:
            bool: True if at least one context was successfully initialized
        """
        console.print("[bold blue][*] Initializing GPU contexts...[/bold blue]")
        
        success_count = 0
        total_devices = len(self.gpu_manager.gpu_devices)
        
        for device in self.gpu_manager.gpu_devices:
            try:
                # Initialize context lock
                self.context_locks[device.device_id] = threading.Lock()
                
                # Initialize based on framework
                if device.framework == GPUFramework.CUDA:
                    success = self._initialize_cuda_context(device)
                elif device.framework == GPUFramework.CUPY:
                    success = self._initialize_cupy_context(device)
                elif device.framework == GPUFramework.OPENCL:
                    success = self._initialize_opencl_context(device)
                else:
                    success = False
                
                self.initialization_status[device.device_id] = success
                if success:
                    success_count += 1
                    console.print(f"[green][+] Context initialized: {device.name}[/green]")
                else:
                    console.print(f"[red][!] Context initialization failed: {device.name}[/red]")
                    
            except Exception as e:
                logger.error(f"Context initialization error for device {device.device_id}: {e}")
                self.initialization_status[device.device_id] = False
        
        if success_count > 0:
            console.print(f"[bold green][+] GPU contexts initialized: {success_count}/{total_devices} devices[/bold green]")
            return True
        else:
            console.print("[red][!] No GPU contexts could be initialized[/red]")
            return False
    
    def _initialize_cuda_context(self, device: GPUDevice) -> bool:
        """Initialize CUDA context for device."""
        if not PYCUDA_AVAILABLE:
            return False
        
        try:
            # Create CUDA context
            cuda_device = cuda.Device(device.device_id)
            context = cuda_device.make_context()
            
            # Test context with a simple operation
            test_array = cuda.mem_alloc(1024)  # Allocate 1KB
            cuda.memset_d8(test_array, 0, 1024)  # Clear memory
            test_array.free()  # Free test memory
            
            # Store context
            self.cuda_contexts[device.device_id] = context
            self.gpu_manager.active_contexts[device.device_id] = context
            
            logger.info(f"CUDA context initialized for device {device.device_id}: {device.name}")
            return True
            
        except Exception as e:
            logger.error(f"CUDA context initialization failed for device {device.device_id}: {e}")
            return False
    
    def _initialize_cupy_context(self, device: GPUDevice) -> bool:
        """Initialize CuPy context for device."""
        if not CUPY_AVAILABLE:
            return False
        
        try:
            # Set CuPy device
            with cp.cuda.Device(device.device_id):
                # Test context with a simple operation
                test_array = cp.zeros(1024, dtype=cp.uint8)
                test_sum = cp.sum(test_array)  # Simple operation
                
                # Store device reference
                cupy_device = cp.cuda.Device(device.device_id)
                self.cupy_contexts[device.device_id] = cupy_device
                self.gpu_manager.active_contexts[device.device_id] = cupy_device
                
                logger.info(f"CuPy context initialized for device {device.device_id}: {device.name}")
                return True
                
        except Exception as e:
            logger.error(f"CuPy context initialization failed for device {device.device_id}: {e}")
            return False
    
    def _initialize_opencl_context(self, device: GPUDevice) -> bool:
        """Initialize OpenCL context and command queue for device."""
        if not PYOPENCL_AVAILABLE:
            return False
        
        try:
            # Find the OpenCL device
            opencl_device = self._find_opencl_device(device)
            if not opencl_device:
                return False
            
            # Create OpenCL context
            context = cl.Context([opencl_device])
            
            # Create command queue
            queue = cl.CommandQueue(context)
            
            # Test context with a simple operation
            test_buffer = cl.Buffer(context, cl.mem_flags.READ_WRITE, size=1024)
            cl.enqueue_fill_buffer(queue, test_buffer, b'\x00', 0, 1024)
            queue.finish()
            
            # Store context and queue
            self.opencl_contexts[device.device_id] = {
                'context': context,
                'queue': queue,
                'device': opencl_device
            }
            self.gpu_manager.active_contexts[device.device_id] = context
            
            logger.info(f"OpenCL context initialized for device {device.device_id}: {device.name}")
            return True
            
        except Exception as e:
            logger.error(f"OpenCL context initialization failed for device {device.device_id}: {e}")
            return False
    
    def _find_opencl_device(self, gpu_device: GPUDevice) -> Optional[Any]:
        """Find corresponding OpenCL device object."""
        try:
            platforms = cl.get_platforms()
            
            for platform in platforms:
                try:
                    devices = platform.get_devices(cl.device_type.GPU)
                    
                    for device in devices:
                        # Match by name (simplified matching)
                        if device.name.strip() == gpu_device.name:
                            return device
                            
                except cl.RuntimeError:
                    continue
                    
        except Exception as e:
            logger.debug(f"OpenCL device search failed: {e}")
        
        return None
    
    @contextmanager
    def get_cuda_context(self, device_id: int):
        """Get CUDA context with proper locking."""
        if device_id not in self.cuda_contexts:
            raise RuntimeError(f"CUDA context not initialized for device {device_id}")
        
        with self.context_locks[device_id]:
            context = self.cuda_contexts[device_id]
            try:
                context.push()
                yield context
            finally:
                context.pop()
    
    @contextmanager
    def get_cupy_context(self, device_id: int):
        """Get CuPy context with proper device selection."""
        if device_id not in self.cupy_contexts:
            raise RuntimeError(f"CuPy context not initialized for device {device_id}")
        
        with self.context_locks[device_id]:
            cupy_device = self.cupy_contexts[device_id]
            with cupy_device:
                yield cupy_device
    
    @contextmanager
    def get_opencl_context(self, device_id: int):
        """Get OpenCL context and command queue."""
        if device_id not in self.opencl_contexts:
            raise RuntimeError(f"OpenCL context not initialized for device {device_id}")
        
        with self.context_locks[device_id]:
            opencl_data = self.opencl_contexts[device_id]
            yield opencl_data['context'], opencl_data['queue']
    
    def recover_context(self, device_id: int) -> bool:
        """
        Recover GPU context after driver failure.
        
        Args:
            device_id: Device ID to recover
            
        Returns:
            bool: True if recovery successful
        """
        device = self.gpu_manager.get_device_by_id(device_id)
        if not device:
            return False
        
        # Check recovery attempt limit
        attempts = self.context_recovery_attempts.get(device_id, 0)
        if attempts >= self.max_recovery_attempts:
            logger.error(f"Maximum recovery attempts reached for device {device_id}")
            return False
        
        console.print(f"[yellow][*] Attempting context recovery for device {device_id}: {device.name}[/yellow]")
        
        try:
            # Clean up existing context
            self._cleanup_device_context(device_id)
            
            # Wait a moment for driver to stabilize
            time.sleep(1.0)
            
            # Reinitialize context
            success = False
            if device.framework == GPUFramework.CUDA:
                success = self._initialize_cuda_context(device)
            elif device.framework == GPUFramework.CUPY:
                success = self._initialize_cupy_context(device)
            elif device.framework == GPUFramework.OPENCL:
                success = self._initialize_opencl_context(device)
            
            # Update recovery attempts
            self.context_recovery_attempts[device_id] = attempts + 1
            
            if success:
                console.print(f"[green][+] Context recovery successful for device {device_id}[/green]")
                # Reset recovery counter on success
                self.context_recovery_attempts[device_id] = 0
                return True
            else:
                console.print(f"[red][!] Context recovery failed for device {device_id}[/red]")
                return False
                
        except Exception as e:
            logger.error(f"Context recovery error for device {device_id}: {e}")
            self.context_recovery_attempts[device_id] = attempts + 1
            return False
    
    def _cleanup_device_context(self, device_id: int):
        """Clean up context for a specific device."""
        try:
            # Remove from active contexts
            if device_id in self.gpu_manager.active_contexts:
                del self.gpu_manager.active_contexts[device_id]
            
            # Clean up CUDA context
            if device_id in self.cuda_contexts:
                try:
                    context = self.cuda_contexts[device_id]
                    context.detach()
                except:
                    pass
                del self.cuda_contexts[device_id]
            
            # Clean up CuPy context
            if device_id in self.cupy_contexts:
                del self.cupy_contexts[device_id]
            
            # Clean up OpenCL context
            if device_id in self.opencl_contexts:
                del self.opencl_contexts[device_id]
            
            # Mark as not initialized
            self.initialization_status[device_id] = False
            
        except Exception as e:
            logger.debug(f"Context cleanup error for device {device_id}: {e}")
    
    def cleanup_all_contexts(self):
        """Clean up all GPU contexts."""
        console.print("[yellow][*] Cleaning up GPU contexts...[/yellow]")
        
        for device_id in list(self.initialization_status.keys()):
            self._cleanup_device_context(device_id)
        
        # Clear all tracking dictionaries
        self.cuda_contexts.clear()
        self.cupy_contexts.clear()
        self.opencl_contexts.clear()
        self.context_locks.clear()
        self.initialization_status.clear()
        self.context_recovery_attempts.clear()
        self.gpu_manager.active_contexts.clear()
        
        logger.info("All GPU contexts cleaned up")
    
    def get_context_status(self) -> Dict[int, Dict[str, Any]]:
        """Get status of all GPU contexts."""
        status = {}
        
        for device_id, initialized in self.initialization_status.items():
            device = self.gpu_manager.get_device_by_id(device_id)
            
            status[device_id] = {
                'device_name': device.name if device else f"Device {device_id}",
                'framework': device.framework.value if device else "unknown",
                'initialized': initialized,
                'recovery_attempts': self.context_recovery_attempts.get(device_id, 0),
                'has_lock': device_id in self.context_locks,
                'active_context': device_id in self.gpu_manager.active_contexts
            }
        
        return status
    
    def test_context_functionality(self, device_id: int) -> bool:
        """Test if GPU context is functional."""
        device = self.gpu_manager.get_device_by_id(device_id)
        if not device or not self.initialization_status.get(device_id, False):
            return False
        
        try:
            if device.framework == GPUFramework.CUDA:
                return self._test_cuda_context(device_id)
            elif device.framework == GPUFramework.CUPY:
                return self._test_cupy_context(device_id)
            elif device.framework == GPUFramework.OPENCL:
                return self._test_opencl_context(device_id)
        except Exception as e:
            logger.error(f"Context functionality test failed for device {device_id}: {e}")
        
        return False
    
    def _test_cuda_context(self, device_id: int) -> bool:
        """Test CUDA context functionality."""
        try:
            with self.get_cuda_context(device_id):
                # Simple memory allocation test
                test_mem = cuda.mem_alloc(1024)
                cuda.memset_d8(test_mem, 42, 1024)
                test_mem.free()
                return True
        except Exception as e:
            logger.debug(f"CUDA context test failed: {e}")
            return False
    
    def _test_cupy_context(self, device_id: int) -> bool:
        """Test CuPy context functionality."""
        try:
            with self.get_cupy_context(device_id):
                # Simple array operation test
                test_array = cp.ones(1000, dtype=cp.float32)
                result = cp.sum(test_array)
                return float(result) == 1000.0
        except Exception as e:
            logger.debug(f"CuPy context test failed: {e}")
            return False
    
    def _test_opencl_context(self, device_id: int) -> bool:
        """Test OpenCL context functionality."""
        try:
            with self.get_opencl_context(device_id) as (context, queue):
                # Simple buffer operation test
                test_buffer = cl.Buffer(context, cl.mem_flags.READ_WRITE, size=1024)
                cl.enqueue_fill_buffer(queue, test_buffer, b'\x42', 0, 1024)
                queue.finish()
                return True
        except Exception as e:
            logger.debug(f"OpenCL context test failed: {e}")
            return False
    
    def get_available_contexts(self) -> List[int]:
        """Get list of device IDs with functional contexts."""
        available = []
        
        for device_id in self.initialization_status:
            if self.initialization_status[device_id] and self.test_context_functionality(device_id):
                available.append(device_id)
        
        return available


# Update the EnhancedGPUManager to include context management
def _add_context_management_to_gpu_manager():
    """Add context management methods to EnhancedGPUManager."""
    
    def initialize_gpu_contexts(self) -> bool:
        """Initialize GPU contexts for multi-framework support."""
        if not hasattr(self, 'context_manager'):
            self.context_manager = GPUContextManager(self)
        
        return self.context_manager.initialize_gpu_contexts()
    
    def get_context_manager(self) -> GPUContextManager:
        """Get the context manager instance."""
        if not hasattr(self, 'context_manager'):
            self.context_manager = GPUContextManager(self)
        return self.context_manager
    
    def cleanup_contexts(self):
        """Clean up all GPU contexts."""
        if hasattr(self, 'context_manager'):
            self.context_manager.cleanup_all_contexts()
    
    def recover_device_context(self, device_id: int) -> bool:
        """Recover context for a specific device."""
        if hasattr(self, 'context_manager'):
            return self.context_manager.recover_context(device_id)
        return False
    
    # Add methods to EnhancedGPUManager class
    EnhancedGPUManager.initialize_gpu_contexts = initialize_gpu_contexts
    EnhancedGPUManager.get_context_manager = get_context_manager
    EnhancedGPUManager.cleanup_contexts = cleanup_contexts
    EnhancedGPUManager.recover_device_context = recover_device_context

# Apply the context management integration
_add_context_management_to_gpu_manager()