#!/usr/bin/env python3
"""
Test script for Hash Cracker GPU Integration
Tests the integration of Enhanced GPU Manager with the existing hash cracker
"""

import sys
import os
import hashlib

# Add the spectra module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_hash_cracker_gpu_integration():
    """Test hash cracker with enhanced GPU manager integration."""
    print("=" * 60)
    print("Testing Hash Cracker GPU Integration")
    print("=" * 60)
    
    try:
        from spectra.modules.hash_cracker import AdvancedHashCracker
        
        # Create a simple test hash (MD5 of "test123")
        test_password = "test123"
        test_hash = hashlib.md5(test_password.encode()).hexdigest()
        
        print(f"Test password: {test_password}")
        print(f"Test hash (MD5): {test_hash}")
        print()
        
        # Initialize hash cracker with GPU enabled
        print("Initializing AdvancedHashCracker with GPU enabled...")
        cracker = AdvancedHashCracker(
            hash_target=test_hash,
            hash_type='md5',
            use_gpu=True,
            verbose=True
        )
        
        print(f"GPU enabled: {cracker.use_gpu}")
        if cracker.use_gpu and cracker.gpu_manager:
            print(f"GPU devices detected: {len(cracker.gpu_manager.gpu_devices)}")
            
            if cracker.gpu_manager.gpu_devices:
                best_device = cracker.gpu_manager.get_best_device()
                print(f"Best GPU: {best_device.name}")
                print(f"Performance score: {best_device.performance_score:.1f}")
                print(f"Memory: {best_device.memory_total / (1024**3):.1f} GB")
                print(f"Framework: {best_device.framework.value}")
                
                # Test context initialization
                if hasattr(cracker.gpu_manager, 'context_manager'):
                    context_status = cracker.gpu_manager.get_context_manager().get_context_status()
                    print(f"GPU contexts initialized: {len(context_status)} devices")
                    
                    for device_id, status in context_status.items():
                        print(f"  Device {device_id}: {status['initialized']}")
        else:
            print("No GPU acceleration available")
        
        print("\n" + "=" * 60)
        print("Integration test completed successfully!")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gpu_manager_standalone():
    """Test the GPU manager standalone functionality."""
    print("\n" + "=" * 60)
    print("Testing GPU Manager Standalone")
    print("=" * 60)
    
    try:
        from spectra.modules.gpu_manager import GPUManagerIntegration
        
        # Create enhanced GPU manager
        gpu_manager = GPUManagerIntegration.create_enhanced_gpu_manager()
        
        # Get acceleration info
        gpu_info = GPUManagerIntegration.get_gpu_acceleration_info(gpu_manager)
        
        print("GPU Acceleration Info:")
        print(f"  Available: {gpu_info['available']}")
        print(f"  Message: {gpu_info['message']}")
        
        if gpu_info['available']:
            best_device = gpu_info['best_device']
            print(f"  Best Device: {best_device['name']}")
            print(f"  Vendor: {best_device['vendor']}")
            print(f"  Framework: {best_device['framework']}")
            print(f"  Memory: {best_device['memory_gb']:.1f} GB")
            print(f"  Compute Units: {best_device['compute_units']}")
            print(f"  Performance Score: {best_device['performance_score']:.1f}")
            print(f"  Estimated Speedup: {gpu_info['estimated_speedup']:.0f}x")
        
        return True
        
    except Exception as e:
        print(f"Standalone test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    success = True
    
    # Test GPU manager standalone
    if not test_gpu_manager_standalone():
        success = False
    
    # Test hash cracker integration
    if not test_hash_cracker_gpu_integration():
        success = False
    
    if success:
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("Enhanced GPU Manager successfully integrated with Hash Cracker")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("SOME TESTS FAILED!")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    sys.exit(main())