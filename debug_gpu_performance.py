#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debug script to check if GPU is really being used or falling back to CPU
"""

import sys
import os
import hashlib
import time

# Add the spectra module to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spectra.modules.hash_cracker import AdvancedHashCracker

def debug_gpu_usage():
    """Debug GPU usage to see if it's really using GPU or falling back to CPU."""
    print("🔍 DEBUG: Verificando se GPU está sendo usada ou fazendo fallback para CPU")
    print("=" * 70)
    
    # Test hash
    test_password = "hello"
    test_hash = hashlib.md5(test_password.encode()).hexdigest()
    print(f"Target hash: {test_hash}")
    print(f"Target password: {test_password}")
    
    # Create hash cracker with GPU enabled
    cracker = AdvancedHashCracker(test_hash, 'md5', use_gpu=True, verbose=True)
    
    print(f"\n📊 GPU Status:")
    print(f"  use_gpu: {cracker.use_gpu}")
    print(f"  gpu_manager exists: {cracker.gpu_manager is not None}")
    
    if cracker.gpu_manager:
        print(f"  gpu_manager.is_gpu_available(): {cracker.gpu_manager.is_gpu_available()}")
        best_device = cracker.gpu_manager.get_best_device()
        if best_device:
            print(f"  Best device: {best_device.name}")
            print(f"  Framework: {best_device.framework.value}")
        else:
            print(f"  No best device found")
    
    # Test batch processing
    test_batch = [test_password, "wrong1", "wrong2", "wrong3", "wrong4"]
    
    print(f"\n🧪 Testing batch processing with {len(test_batch)} passwords...")
    
    # Test individual GPU methods to see which ones work
    print(f"\n🔬 Testing individual GPU methods:")
    
    # Test CUDA
    try:
        print(f"  Testing CUDA...")
        cuda_result = cracker._gpu_hash_batch_cuda(test_batch)
        print(f"    CUDA result: {cuda_result}")
        if cuda_result == test_password:
            print(f"    ✅ CUDA working correctly!")
        elif cuda_result is None:
            print(f"    ❌ CUDA returned None (likely fallback to CPU)")
        else:
            print(f"    ❌ CUDA returned wrong result")
    except Exception as e:
        print(f"    ❌ CUDA failed: {e}")
    
    # Test CuPy
    try:
        print(f"  Testing CuPy...")
        cupy_result = cracker._gpu_hash_batch_cupy(test_batch)
        print(f"    CuPy result: {cupy_result}")
        if cupy_result == test_password:
            print(f"    ✅ CuPy working correctly!")
        elif cupy_result is None:
            print(f"    ❌ CuPy returned None (likely fallback to CPU)")
        else:
            print(f"    ❌ CuPy returned wrong result")
    except Exception as e:
        print(f"    ❌ CuPy failed: {e}")
    
    # Test OpenCL
    try:
        print(f"  Testing OpenCL...")
        opencl_result = cracker._gpu_hash_batch_opencl(test_batch)
        print(f"    OpenCL result: {opencl_result}")
        if opencl_result == test_password:
            print(f"    ✅ OpenCL working correctly!")
        elif opencl_result is None:
            print(f"    ❌ OpenCL returned None (likely fallback to CPU)")
        else:
            print(f"    ❌ OpenCL returned wrong result")
    except Exception as e:
        print(f"    ❌ OpenCL failed: {e}")
    
    # Test CPU for comparison
    try:
        print(f"  Testing CPU...")
        cpu_result = cracker._cpu_hash_batch(test_batch)
        print(f"    CPU result: {cpu_result}")
        if cpu_result == test_password:
            print(f"    ✅ CPU working correctly!")
        else:
            print(f"    ❌ CPU failed")
    except Exception as e:
        print(f"    ❌ CPU failed: {e}")
    
    # Test the main processing method
    print(f"\n🎯 Testing main _test_passwords_chunk method:")
    start_time = time.time()
    main_result = cracker._test_passwords_chunk(test_batch)
    elapsed_time = time.time() - start_time
    
    print(f"  Result: {main_result}")
    print(f"  Time: {elapsed_time:.4f}s")
    print(f"  Rate: {len(test_batch)/elapsed_time:.0f} hashes/second")
    
    if main_result == test_password:
        print(f"  ✅ Main method working!")
    else:
        print(f"  ❌ Main method failed!")
    
    # Performance analysis
    print(f"\n📈 Performance Analysis:")
    rate = len(test_batch) / elapsed_time if elapsed_time > 0 else float('inf')
    
    if rate > 1000000:  # > 1M h/s
        print(f"  🚀 EXCELLENT: {rate:.0f} h/s - Likely using GPU!")
    elif rate > 100000:  # > 100K h/s
        print(f"  ✅ GOOD: {rate:.0f} h/s - Possibly using GPU")
    elif rate > 10000:   # > 10K h/s
        print(f"  ⚠️  MODERATE: {rate:.0f} h/s - Likely using CPU")
    else:
        print(f"  ❌ SLOW: {rate:.0f} h/s - Definitely using CPU or has issues")
    
    # Check library availability
    print(f"\n📚 Library Availability:")
    try:
        import pycuda
        print(f"  ✅ PyCUDA available")
    except ImportError:
        print(f"  ❌ PyCUDA not available")
    
    try:
        import cupy
        print(f"  ✅ CuPy available")
    except ImportError:
        print(f"  ❌ CuPy not available")
    
    try:
        import pyopencl
        print(f"  ✅ PyOpenCL available")
    except ImportError:
        print(f"  ❌ PyOpenCL not available")
    
    # Final diagnosis
    print(f"\n🏥 DIAGNÓSTICO:")
    if rate < 500000:  # Less than 500K h/s
        print(f"  🚨 PROBLEMA: Taxa muito baixa ({rate:.0f} h/s)")
        print(f"  🔍 CAUSA PROVÁVEL: GPU kernels falhando → Fallback para CPU")
        print(f"  💡 SOLUÇÃO: Verificar logs de erro dos kernels GPU")
        print(f"  📋 AÇÃO: Instalar bibliotecas GPU (pip install pycuda cupy pyopencl)")
    else:
        print(f"  ✅ NORMAL: Taxa adequada para GPU ({rate:.0f} h/s)")

if __name__ == "__main__":
    debug_gpu_usage()