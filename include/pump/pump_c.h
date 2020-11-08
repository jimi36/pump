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

#ifndef pump_c_h
#define pump_c_h

#if defined(pump_EXPORTS)
#define LIB_PUMP_C __declspec(dllexport)
#else
#define LIB_PUMP_C
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /*********************************************************************************
     * Pump c library init
     ********************************************************************************/
	LIB_PUMP_C void pump_c_init();

    /*********************************************************************************
     * Pump c library uninit
     ********************************************************************************/
	LIB_PUMP_C void pump_c_uninit();

    /*********************************************************************************
	 * Pump c service
     ********************************************************************************/
	typedef void* pump_c_service;

	/*********************************************************************************
	 * Pump c service create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_service pump_c_service_create(int with_poller);

    /*********************************************************************************
     * Pump c service destory
     ********************************************************************************/
	LIB_PUMP_C void pump_c_service_destory(pump_c_service sv);

    /*********************************************************************************
     * Pump c service start
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
     ********************************************************************************/
	LIB_PUMP_C int pump_c_service_start(pump_c_service sv);

    /*********************************************************************************
     * Pump c service stop
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
     ********************************************************************************/
	LIB_PUMP_C int pump_c_service_stop(pump_c_service sv);

    /*********************************************************************************
	 * Pump c timer
     ********************************************************************************/
	typedef void* pump_c_timer;

    /*********************************************************************************
	 * Pump c timer timeout callback function
     ********************************************************************************/
	typedef void (*pump_c_timeout_callback)();

	/*********************************************************************************
	 * Pump c timer create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_timer pump_c_timer_create(int timeout_ms,
                                                int repeated, 
                                                pump_c_timeout_callback cb);

	/*********************************************************************************
	 * Pump c service destory
	 ********************************************************************************/
	LIB_PUMP_C void pump_c_timer_destory(pump_c_timer timer);

    /*********************************************************************************
     * Pump c timer start
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
     ********************************************************************************/
	LIB_PUMP_C int pump_c_timer_start(pump_c_service sv, pump_c_timer timer);

    /*********************************************************************************
     * Pump c timer stop
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
     ********************************************************************************/
	LIB_PUMP_C int pump_c_timer_stop(pump_c_timer timer);

    /*********************************************************************************
	 * Pump c dialer
     ********************************************************************************/
	typedef void* pump_c_dialer;

    /*********************************************************************************
	 * Pump c acceptor
     ********************************************************************************/
	typedef void* pump_c_acceptor;

    /*********************************************************************************
	 * Pump c transport
     ********************************************************************************/
	typedef void* pump_c_transport;
	
    /*********************************************************************************
	 * Pump c acceptor callbacks
     ********************************************************************************/
	struct pump_c_acceptor_callbacks {
		// Accepted callback
		void (*accepted_cb)(pump_c_transport, pump_c_transport);
		// Acceptor Stopped calloback
		void (*stopped_cb)(pump_c_transport);
	};

    /*********************************************************************************
	 * Pump c dialer callbacks
     ********************************************************************************/
    struct pump_c_dialer_callbacks {
        // Dialed callback
        void (*dialed_cb)(pump_c_dialer, pump_c_transport, int);
        // Dialer timouted callback
        void (*timeouted_cb)(pump_c_dialer);
        // Dialer stopped callback
        void (*stopped_cb)(pump_c_dialer);
    };

    /*********************************************************************************
	 * Pump c transport callbacks
     ********************************************************************************/
    struct pump_c_transport_callbacks {
        // Read callback for tcp and tls
        void (*read_cb)(pump_c_transport, const char*, int);
        // Read from callback for udp
        void (*read_from_cb)(pump_c_transport, const char*, int, const char*, int);
        // Transport disconnected callback
        void (*disconnected_cb)(pump_c_transport);
        // Transport stopped callback
        void (*stopped_cb)(pump_c_transport);
    };

	/*********************************************************************************
	 * Pump c tcp acceptor create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_acceptor pump_c_tcp_acceptor_create(const char *ip, int port);

	/*********************************************************************************
	 * Pump c tls acceptor create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_acceptor pump_c_tls_acceptor_create(const char *ip, 
                                                          int port,
                                                          const char *cert, 
                                                          const char *key);

	/*********************************************************************************
	 * Pump c acceptor destory
	 ********************************************************************************/                                              
	LIB_PUMP_C void pump_c_acceptor_destory(pump_c_acceptor acceptor);

	/*********************************************************************************
	 * Pump c acceptor start
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_acceptor_start(pump_c_service sv,
                                         pump_c_acceptor acceptor, 
                                         pump_c_acceptor_callbacks cbs);

	/*********************************************************************************
	 * Pump c acceptor stop
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_acceptor_stop(pump_c_acceptor acceptor);

	/*********************************************************************************
	 * Pump c tcp dialer create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_dialer pump_c_tcp_dialer_create(const char *local_ip, 
                                                      int local_port,
		                                              const char *remote_ip, 
                                                      int remote_port);

	/*********************************************************************************
	 * Pump c tls dialer create
	 ********************************************************************************/
	LIB_PUMP_C pump_c_dialer pump_c_tls_dialer_create(const char *local_ip, 
                                                      int local_port,
                                                      const char *remote_ip, 
                                                      int remote_port);
                                                      
	/*********************************************************************************
	 * Pump c dialer destory
	 ********************************************************************************/                                              
	LIB_PUMP_C void pump_c_dialer_destory(pump_c_dialer dialer);

	/*********************************************************************************
	 * Pump c dialer start
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_dialer_start(pump_c_service sv,
                                       pump_c_dialer dialer, 
                                       pump_c_dialer_callbacks cbs);

	/*********************************************************************************
	 * Pump c dialer stop
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_dialer_stop(pump_c_dialer dialer);

	/*********************************************************************************
	 * Pump c transport destory
	 ********************************************************************************/                                              
	LIB_PUMP_C void pump_c_transport_destory(pump_c_transport transp);
    
	/*********************************************************************************
	 * Pump c transport start
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_transport_start(pump_c_service sv,
                                          pump_c_transport transp, 
                                          pump_c_transport_callbacks cbs);

	/*********************************************************************************
	 * Pump c transport stop
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_transport_stop(pump_c_transport transp);

	/*********************************************************************************
	 * Pump c transport send
     * When successful, this returns 0.
     * When an error occurs, this returns -1.
	 ********************************************************************************/
	LIB_PUMP_C int pump_c_transport_send(pump_c_transport transp, 
                                         const char *b, 
                                         int size);

#ifdef __cplusplus    
}
#endif

#endif