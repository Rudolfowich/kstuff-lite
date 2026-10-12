import urllib.request, http.client, html

def get_freebsd_syscalls():
    data = urllib.request.urlopen('https://raw.githubusercontent.com/freebsd/freebsd/stable/9/sys/kern/syscalls.master').read().decode('ascii')
    data = '\n'.join(i.strip() for i in data.split('\n') if not i.startswith(';')).replace('\\\n', ' ')
    assert data.startswith('$FreeBSD$\n')
    data = data[10:]
    ans = {}
    for i in data.split('\n'):
        i = i.strip()
        if not i or 'STD' not in i.split() or i.startswith('#include'): continue
        name = i.split('(', 1)[0].split()[-1]
        idx = int(i.split()[0])
        ans[idx] = name
    return ans

def get_sony_syscalls():
    # TODO: PS5-specific syscalls
    try:
        req = urllib.request.Request(
            'http://web.archive.org/web/20210124215126js_/https://psdevwiki.com/ps4/edit/Syscalls',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        r = urllib.request.urlopen(req, timeout=5)
        data = html.unescape(r.read().decode('latin-1').split('<textarea ', 1)[1].split('</textarea>', 1)[0])
        ans = {}
        for i in data.split('\n'):
            if i.startswith('| '):
                try:
                    syscno, fw, syscname, proto, notes = i[2:].split(' || ')
                    syscno = int(syscno)
                except ValueError: continue
                if syscname.startswith('sys_'):
                    ans[syscno] = syscname[4:]
        if ans:
            return ans
    except Exception as e:
        import sys
        sys.stderr.write(f"Notice: using cached Sony syscall table ({e})\n")

    # Offline fallback table (crucial for linking lib-elf-ps5.a e.g. dynlib_dlsym)
    return {
        532: 'regmgr_call', 533: 'jitshm_create', 534: 'jitshm_alias',
        535: 'dl_get_list', 536: 'dl_get_info', 537: 'dl_notify_event',
        538: 'evf_create', 539: 'evf_delete', 540: 'evf_open', 541: 'evf_close',
        542: 'evf_wait', 543: 'evf_trywait', 544: 'evf_set', 545: 'evf_clear', 546: 'evf_cancel',
        547: 'query_memory_protection', 548: 'batch_map', 549: 'osem_create', 550: 'osem_delete',
        551: 'osem_open', 552: 'osem_close', 553: 'osem_wait', 554: 'osem_trywait',
        555: 'osem_post', 556: 'osem_cancel', 557: 'namedobj_create', 558: 'namedobj_delete',
        559: 'set_vm_container', 560: 'debug_init', 561: 'suspend_process', 562: 'resume_process',
        563: 'opmc_enable', 564: 'opmc_disable', 565: 'opmc_set_ctl', 566: 'opmc_set_ctr', 567: 'opmc_get_ctr',
        568: 'budget_create', 569: 'budget_delete', 570: 'budget_get', 571: 'budget_set',
        572: 'virtual_query', 573: 'mdbg_call', 574: 'sblock_create', 575: 'sblock_delete',
        576: 'sblock_enter', 577: 'sblock_exit', 578: 'sblock_xenter', 579: 'sblock_xexit',
        580: 'eport_create', 581: 'eport_delete', 582: 'eport_trigger', 583: 'eport_open', 584: 'eport_close',
        585: 'is_in_sandbox', 586: 'dmem_container', 587: 'get_authinfo', 588: 'mname',
        589: 'dynlib_dlopen', 590: 'dynlib_dlclose', 591: 'dynlib_dlsym', 592: 'dynlib_get_list',
        593: 'dynlib_get_info', 594: 'dynlib_load_prx', 595: 'dynlib_unload_prx',
        596: 'dynlib_do_copy_relocations', 597: 'dynlib_prepare_dlclose', 598: 'dynlib_get_proc_param',
        599: 'dynlib_process_needed_and_relocate', 600: 'sandbox_path', 601: 'mdbg_service',
        602: 'randomized_path', 603: 'rdup', 604: 'dl_get_metadata', 605: 'workaround8849',
        606: 'is_development_mode', 607: 'get_self_auth_info', 608: 'dynlib_get_info_ex',
        609: 'budget_getid', 610: 'budget_get_ptype', 611: 'get_paging_stats_of_all_threads',
        612: 'get_proc_type_info', 613: 'get_resident_count', 614: 'prepare_to_suspend_process',
        615: 'get_resident_fmem_count', 616: 'thr_get_name', 617: 'set_gpo',
        618: 'get_paging_stats_of_all_objects', 619: 'test_debug_rwmem', 620: 'free_stack',
        621: 'suspend_system', 622: 'ipmimgr_call', 623: 'get_gpo', 624: 'get_vm_map_timestamp',
        625: 'opmc_set_hw', 626: 'opmc_get_hw', 627: 'get_cpu_usage_all', 628: 'mmap_dmem',
        629: 'physhm_open', 630: 'physhm_unlink', 631: 'resume_internal_hdd',
        632: 'thr_suspend_ucontext', 633: 'thr_resume_ucontext', 634: 'thr_get_ucontext',
        635: 'thr_set_ucontext', 636: 'set_timezone_info', 637: 'set_phys_fmem_limit',
        638: 'utc_to_localtime', 639: 'localtime_to_utc', 640: 'set_uevt', 641: 'get_cpu_usage_proc',
        642: 'get_map_statistics', 643: 'set_chicken_switches', 644: 'extend_page_table_pool',
        645: 'extend_page_table_pool2', 646: 'get_kernel_mem_statistics', 647: 'get_sdk_compiled_version',
        648: 'app_state_change', 649: 'dynlib_get_obj_member', 650: 'budget_get_ptype_of_budget',
        651: 'prepare_to_resume_process', 652: 'process_terminate', 653: 'blockpool_open',
        654: 'blockpool_map', 655: 'blockpool_unmap', 656: 'dynlib_get_info_for_libdbg',
        657: 'blockpool_batch', 658: 'fdatasync', 659: 'dynlib_get_list2', 660: 'dynlib_get_info2',
        661: 'aio_submit', 662: 'aio_multi_delete', 663: 'aio_multi_wait', 664: 'aio_multi_poll',
        665: 'aio_get_data', 666: 'aio_multi_cancel', 667: 'get_bio_usage_all', 668: 'aio_create',
        669: 'aio_submit_cmd', 670: 'aio_init', 671: 'get_page_table_stats',
        672: 'dynlib_get_list_for_libdbg', 673: 'blockpool_move', 674: 'virtual_query_all',
        675: 'reserve_2mb_page', 676: 'cpumode_yield', 677: 'get_phys_page_size'
    }

def get_syscalls():
    ans = {}
    ans.update(get_freebsd_syscalls())
    ans.update(get_sony_syscalls())
    return ans

print('section .text')
print('use64')
print('global p_syscall')
print()

for idx, name in sorted(get_syscalls().items()):
    if '#' in name: continue
    print('section .text.'+name+' exec')
    print('global', name)
    print(name+':')
    print('mov eax,', idx)
    if name == 'pipe':
        print('push rbp')
        print('call common_syscall')
        print('pop rbp')
        print('cmp eax, -1')
        print('jz .skip_write')
        print('mov [rdi], eax')
        print('mov [rdi+4], edx')
        print('xor eax, eax')
        print('.skip_write:')
        print('ret')
    else:
        print('jmp common_syscall')

print('''\
section .text.common_syscall exec
common_syscall:
mov r10, [rel p_syscall]
test r10, r10
jnz .jmp
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
push rax
mov r10, [rel addr__dynlib_dlsym]
push r10
mov edi, 0x1
lea rsi, [rel getpid_str]
mov rdx, rsp
call r10
pop r10
pop rax
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
add r10, 7
mov [rel p_syscall], r10
.jmp:
jmp r10

section .text.__error exec
global __error
__error:
mov r10, [rel addr____error]
test r10, r10
jnz .have_error
push rax
mov edi, 0x1
lea rsi, [rel error_str]
mov rdx, rsp
call [rel addr__dynlib_dlsym]
pop r10
.have_error:
jmp r10

section .text.syscall exec
global syscall
$syscall:
mov rax, rdi
mov rdi, rsi
mov rsi, rdx
mov rdx, rcx
mov rcx, r8
mov r8, r9
mov r9, [rsp+8]
jmp common_syscall

section .rodata.getpid_str
getpid_str:
db "getpid", 0

section .rodata.error_str
error_str:
db "__error", 0

section .bss.addr__dynlib_dlsym
global addr__dynlib_dlsym
addr__dynlib_dlsym:
dq 0

section .bss.addr____error
global addr____error
addr____error:
dq 0

section .bss.p_syscall
p_syscall:
dq 0\
''')
