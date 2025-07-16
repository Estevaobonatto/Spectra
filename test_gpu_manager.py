#!/usr/bin/env python3
"""
Test script for Enhanced GPU Manager
Tests GPU detection and management functionality
"""

import sys
import os

# Add the spectra module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from spectra.modules.gpu_manager import (
    EnhancedGPUManager, 
    GPUDeviceSelector, 
    GPUHealthMonitor,
    GPUFramework,
    GPUVendor
)

def test_gpu_detection():
    """Test GPU detection functionality."""
    print("=" * 60)
    print("Testing Enhanced GPU Manager")
    print("=" * 60)
    
    # Create GPU manager
    gpu_manager = EnhancedGPUManager()
    
    # Detect GPUs
    devices = gpu_manager.detect_all_gpus()
    
    print(f"\nDetection Results:")
    print(f"Total devices found: {len(devices)}")
    
    if devices:
        print("\nDevice Details:")
        for i, device in enumerate(devices):
            print(f"\nDevice {i+1}:")
            print(f"  Name: {device.name}")
            print(f"  Vendor: {device.vendor.value}")
            print(f"  Framework: {device.framework.value}")
            print(f"  Memory: {device.memory_total / (1024**3):.1f} GB")
            print(f"  Compute Units: {device.compute_units}")
            print(f"  Performance Score: {device.performance_score:.1f}")
            print(f"  Integrated: {device.is_integrated}")
    
    return gpu_manager

def test_device_selection(gpu_manager):
    """Test device selection algorithms."""
    print("\n" + "=" * 60)
    print("Testing Device Selection")
    print("=" * 60)
    
    if not gpu_manager.gpu_devices:
        print("No GPU devices available for selection testing")
        return
    
    selector = GPUDeviceSelector(gpu_manager)
    
    # Test optimal device selection
    optimal_device = selector.select_optimal_device(
        algorithm="md5",
        batch_size=10000
    )
    
    if optimal_device:
        print(f"\nOptimal device for MD5 (batch=10000):")
        print(f"  Device: {optimal_device.name}")
        print(f"  Score: {optimal_device.performance_score:.1f}")
    
    # Test multi-GPU selection
    multi_gpu = selector.select_multi_gpu_setup(
        target_performance=1000000,  # 1M hashes/sec
        algorithm="sha256"
    )
    
    print(f"\nMulti-GPU setup for SHA256 (target=1M h/s):")
    print(f"  Selected devices: {len(multi_gpu)}")
    for device in multi_gpu:
        print(f"    - {device.name}")

def test_context_management(gpu_manager):
    """Test GPU context management."""
    print("\n" + "=" * 60)
    print("Testing Context Management")
    print("=" * 60)
    
    if not gpu_manager.gpu_devices:
        print("No GPU devices available for context testing")
        return
    
    # Initialize contexts
    success = gpu_manager.initialize_gpu_contexts()
    print(f"Context initialization: {'Success' if success else 'Failed'}")
    
    if success:
        context_manager = gpu_manager.get_context_manager()
        
        # Get context status
        status = context_manager.get_context_status()
        print(f"\nContext Status:")
        for device_id, info in status.items():
            print(f"  Device {device_id} ({info['device_name']}):")
            print(f"    Framework: {info['framework']}")
            print(f"    Initialized: {info['initialized']}")
            print(f"    Functional: {context_manager.test_context_functionality(device_id)}")
        
        # Test available contexts
        available = context_manager.get_available_contexts()
        print(f"\nAvailable contexts: {len(available)} devices")
        
        # Cleanup
        gpu_manager.cleanup_contexts()
        print("Contexts cleaned up")

def test_health_monitoring(gpu_manager):
    """Test GPU health monitoring."""
    print("\n" + "=" * 60)
    print("Testing Health Monitoring")
    print("=" * 60)
    
    if not gpu_manager.gpu_devices:
        print("No GPU devices available for health monitoring testing")
        return
    
    health_monitor = GPUHealthMonitor(gpu_manager)
    
    # Start monitoring briefly
    print("Starting health monitoring for 3 seconds...")
    health_monitor.start_monitoring(interval=0.5)
    
    import time
    time.sleep(3)
    
    health_monitor.stop_monitoring()
    
    # Get health summary
    summary = health_monitor.get_health_summary()
    print(f"\nHealth Summary:")
    for device_id, info in summary.items():
        print(f"  {info['device_name']}:")
        print(f"    Memory Usage: {info['memory_usage_percent']:.1f}%")
        print(f"    Utilization: {info['utilization_percent']:.1f}%")
        print(f"    Temperature: {info['temperature']:.1f}°C")

def main():
    """Main test function."""
    try:
        # Test GPU detection
        gpu_manager = test_gpu_detection()
        
        # Test device selection
        test_device_selection(gpu_manager)
        
        # Test context management
        test_context_management(gpu_manager)
        
        # Test health monitoring
        test_health_monitoring(gpu_manager)
        
        print("\n" + "=" * 60)
        print("All tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())