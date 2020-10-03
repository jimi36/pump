/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pump_toolkit_sort_h
#define pump_toolkit_sort_h

#include "pump/types.h"

namespace pump {
namespace toolkit {

    /*********************************************************************************
     * Swap *a and *b
     ********************************************************************************/
    // template<typename T> inline void swap(T& a, T& b)
    //{
    //	a = a ^ b; b = a ^ b; a = a ^ b;
    //	T tmp = a; a = b; b = tmp;
    //}

    /*********************************************************************************
     * Bubble sort algorithm.
     * a      ---->   array of Comparable items.
     * left   ---->   the left-most index of the subarray.
     * right  ---->   the right-most index of the subarray.
     * range is [left, right)
     ********************************************************************************/
    template <typename T>
    void bubble_sort(const T *a, int32 left, int32 right) {
        for (int32 i = left; i < right; ++i) {
            for (int32 j = i + 1; j < right; ++j) {
                if (a[i] > a[j]) {
                    std::swap(a[i], a[j]);
                }
            }
        }
    }

    /*********************************************************************************
     * Select sort algorithm.
     * a      ---->   array of Comparable items.
     * left   ---->   the left-most index of the subarray.
     * right  ---->   the right-most index of the subarray.
     * range is [left, right)
     ********************************************************************************/
    template <typename T>
    void select_sort(const T *a, int32 left, int32 right) {
        int32 min_pos;
        for (int32 i = left; i < right; ++i) {
            min_pos = i;
            for (int32 j = i + 1; j < right; ++j) {
                if (a[j] < a[min_pos]) {
                    min_pos = j;
                }
            }
            if (i != min_pos) {
                std::swap(a[i], a[min_pos]);
            }
        }
    }

    /*********************************************************************************
     * Insert sort algorithm.
     * a      ---->   array of Comparable items.
     * left   ---->   the left-most index of the subarray.
     * right  ---->   the right-most index of the subarray.
     * range is [left, right)
     ********************************************************************************/
    template <typename T>
    void insert_sort(T *a, int32 left, int32 right) {
        for (int32 i = left + 1; i < right; ++i) {
            T tem = a[i];
            int32 j = i;
            for (; j >= left && tem < a[j - 1]; --j) {
                a[j] = a[j - 1];
            }
            a[j] = tem;
        }
    }

    /*********************************************************************************
     * Get median pos for quick sort algorithm.
     * a      ---->   array of Comparable items.
     * left   ---->   the left-most index of the subarray.
     * right  ---->   the right-most index of the subarray.
     * range is [left, right)
     ********************************************************************************/
    template <typename T>
    int32 __median_pos(T *a, int32 left, int32 right) {
        int32 i = left;
        int32 j = right - 1;
        T pivot = a[left];
        while (i < j) {
            while (a[j] >= pivot && j > i) {
                --j;
            }
            if (j > i) {
                std::swap(a[i++], a[j]);
            }

            while (a[i] <= pivot && i < j) {
                ++i;
            }
            if (i < j) {
                std::swap(a[i], a[j--]);
            }
        }

        return i;
    }

    /*********************************************************************************
     * Quick sort algorithm.
     * a      ---->   array of Comparable items.
     * left   ---->   the left-most index of the subarray.
     * right  ---->   the right-most index of the subarray.
     * range is [left, right)
     ********************************************************************************/
    template <typename T>
    void quick_sort(T *a, int32 left, int32 right) {
        static int32 min_size = 10;

        if (right - left > min_size) {
            int32 pos = __median_pos(a, left, right);
            quick_sort(a, left, pos);
            quick_sort(a, pos + 1, right);
        } else {
            insert_sort(a, left, right);
        }
    }

    /*********************************************************************************
     * Become max heapify for heapsort algorithm.
     * a      ---->   array of Comparable items.
     * s      ---->   size of the array.
     * i      ---->   rott index of the subtree.
     ********************************************************************************/
    template <typename T>
    void __max_heapify(T *a, int32 s, int32 i) {
        int32 l = i * 2;
        int32 r = i * 2 + 1;

        int32 largest = i;
        if (l < s && a[l] > a[i]) {
            largest = l;
        }
        if (r < s && a[r] > a[largest]) {
            largest = r;
        }

        if (largest != i) {
            std::swap(a[i], a[largest]);
            __max_heapify(a, s, largest);
        }
    }

    /*********************************************************************************
     * Build max heap for heapsort algorithm.
     * a      ---->   array of Comparable items.
     * s      ---->   size of the array.
     ********************************************************************************/
    template <typename T>
    void __bulid_max_heap(T *a, int32 s) {
        for (int32 i = s / 2; i >= 0; --i) {
            __max_heapify(a, s, i);
        }
    }

    /*********************************************************************************
     * Heap sort algorithm.
     * a      ---->   array of Comparable items.
     * s      ---->   size of the array.
     ********************************************************************************/
    template <typename T>
    void heap_sort(T *a, int32 s) {
        __bulid_max_heap(a, s);
        for (int32 i = s - 1; i >= 1; --i) {
            std::swap(a[0], a[i]);
            __max_heapify(a, --s, 0);
        }
    }

}  // namespace toolkit
}  // namespace pump

#endif