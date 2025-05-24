
const globalNativeCallbacks = [];
const callLogMap = new Map();

function getThreadId() {
    try {
        return Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0;
    } catch {
        return 0;
    }
}

function getCallId() {
    return `${Date.now()}_${getThreadId()}_${Math.floor(Math.random() * 100000)}`;
}

function formatLog(logLines, callId, funcName) {
    const border = '━'.repeat(45);
    let out = [];
    out.push(`\n\x1b[36m┏${border}\x1b[0m`);
    out.push(`\x1b[36m┃ 调用: ${funcName}  [${callId}]\x1b[0m`);
    logLines.forEach(line => {
        // 参数和返回值缩进
        if (line.startsWith('[arg]')) {
            out.push(`\x1b[32m┣ 参数: ${line.replace('[arg]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('[Promise]')) {
            out.push(`\x1b[35m┣ Promise: ${line.replace('[Promise]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('---- 返回值 ----')) {
            out.push(`\x1b[33m┣ 返回值:\x1b[0m`);
        } else if (line.startsWith('[!]')) {
            out.push(`\x1b[31m┣ 错误: ${line.replace('[!]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('====')) {
            // 跳过
        } else {
            out.push(`\x1b[32m┣ ${line.replace('[arg]', '').trim()}\x1b[0m`);
        }
    });
    out.push(`\x1b[36m┗${border}\x1b[0m\n`);
    return out.join('\n');
}

function printNapiValue(env, value, logLines) {
    if (!value || value.isNull && value.isNull()) {
        logLines.push('[arg] value is NULL');
        return;
    }
    var napi_typeof_addr = Module.findExportByName('qqnt.dll', 'napi_typeof');
    var napi_typeof_fn = new NativeFunction(napi_typeof_addr, 'int', ['pointer', 'pointer', 'pointer']);
    var type_ptr = Memory.alloc(4);
    var status = napi_typeof_fn(env, value, type_ptr);
    if (status !== 0) {
        logLines.push('[!] napi_typeof failed: ' + status);
        return;
    }
    var type = type_ptr.readU32();
    switch (type) {
        case 0: logLines.push('[arg] type: undefined'); break;
        case 1: logLines.push('[arg] type: null'); break;
        case 2: { // boolean
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_bool'), 'int', ['pointer', 'pointer', 'pointer']);
            var ptr = Memory.alloc(4);
            if (fn(env, value, ptr) === 0) logLines.push('[arg] type: boolean, value: ' + (ptr.readU32() ? 'true' : 'false'));
            else logLines.push('[arg] type: boolean, value: <error>');
            break;
        }
        case 3: { // number
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_double'), 'int', ['pointer', 'pointer', 'pointer']);
            var ptr = Memory.alloc(8);
            if (fn(env, value, ptr) === 0) logLines.push('[arg] type: number, value: ' + ptr.readDouble());
            else logLines.push('[arg] type: number, value: <error>');
            break;
        }
        case 4: { // string
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8'), 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
            var buf = Memory.alloc(1024), copied = Memory.alloc(8);
            if (fn(env, value, buf, 1023, copied) === 0) logLines.push('[arg] type: string, value: ' + buf.readUtf8String());
            else logLines.push('[arg] type: string, value: <error>');
            break;
        }
        case 6: { // object
            try {
                var napi_get_global = Module.findExportByName('qqnt.dll', 'napi_get_global');
                var napi_get_global_fn = napi_get_global ? new NativeFunction(napi_get_global, 'int', ['pointer', 'pointer']) : null;
                var global_ptr = Memory.alloc(Process.pointerSize);
                if (napi_get_global_fn) napi_get_global_fn(env, global_ptr);
                else {
                    var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
                    var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
                    var global_name = Memory.allocUtf8String("globalThis");
                    napi_get_named_property_fn(env, env, global_name, global_ptr);
                }
                var global_obj = global_ptr.readPointer();
                var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
                var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
                var json_name = Memory.allocUtf8String("JSON");
                var json_ptr = Memory.alloc(Process.pointerSize);
                napi_get_named_property_fn(env, global_obj, json_name, json_ptr);
                var json_obj = json_ptr.readPointer();
                var stringify_name = Memory.allocUtf8String("stringify");
                var stringify_ptr = Memory.alloc(Process.pointerSize);
                napi_get_named_property_fn(env, json_obj, stringify_name, stringify_ptr);
                var stringify_fn = stringify_ptr.readPointer();
                var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
                var napi_call_function_fn = new NativeFunction(napi_call_function, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']);
                var stringify_argv = Memory.alloc(Process.pointerSize);
                stringify_argv.writePointer(value);
                var stringify_result_ptr = Memory.alloc(Process.pointerSize);
                if (napi_call_function_fn(env, json_obj, stringify_fn, 1, stringify_argv, stringify_result_ptr) === 0) {
                    var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8'), 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
                    var buf = Memory.alloc(4096), copied = Memory.alloc(8);
                    fn(env, stringify_result_ptr.readPointer(), buf, 4095, copied);
                    logLines.push('[arg] type: object, JSON: ' + buf.readUtf8String());
                } else {
                    logLines.push('[arg] type: object, JSON: <stringify error>');
                }
            } catch (e) {
                logLines.push('[arg] type: object, JSON: <exception> ' + e);
            }
            break;
        }
        case 9: { // bigint
            var addr = Module.findExportByName('qqnt.dll', 'napi_get_value_bigint_words');
            if (addr) {
                var fn = new NativeFunction(addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                var sign_ptr = Memory.alloc(4), word_count_ptr = Memory.alloc(8);
                word_count_ptr.writeU64(4);
                var words_ptr = Memory.alloc(8 * 4);
                if (fn(env, value, sign_ptr, word_count_ptr, words_ptr) === 0) {
                    var sign = sign_ptr.readU32(), word_count = word_count_ptr.readU64();
                    var words = [];
                    for (var i = 0; i < word_count; i++) words.push(words_ptr.add(i * 8).readU64());
                    var hex = words.map(w => w.toString(16).padStart(16, '0')).reverse().join('');
                    var prefix = sign ? '-' : '';
                    logLines.push('[arg] type: bigint, value: ' + prefix + '0x' + hex);
                } else {
                    logLines.push('[arg] type: bigint, value: <error>');
                }
            } else {
                logLines.push('[arg] type: bigint, value: <napi_get_value_bigint_words not found>');
            }
            break;
        }
        default: logLines.push('[arg] type: ' + type);
    }
}

function isPromise(env, value) {
    try {
        var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        var constructor_name = Memory.allocUtf8String("constructor");
        var constructor_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, value, constructor_name, constructor_ptr) !== 0) return false;
        var constructor = constructor_ptr.readPointer();

        var name_name = Memory.allocUtf8String("name");
        var name_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, constructor, name_name, name_ptr) !== 0) return false;
        var napi_get_value_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8');
        var napi_get_value_string_utf8_fn = new NativeFunction(napi_get_value_string_utf8, 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
        var buf = Memory.alloc(64), copied = Memory.alloc(8);
        if (napi_get_value_string_utf8_fn(env, name_ptr.readPointer(), buf, 63, copied) !== 0) return false;
        var name = buf.readUtf8String();
        return name === "Promise";
    } catch (e) {
        return false;
    }
}

function callPromiseThen(env, promise, logLines, callId, funcName) {
    try {
        var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        var then_name = Memory.allocUtf8String("then");
        var then_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, promise, then_name, then_ptr) !== 0) {
            logLines.push('[Promise] 获取 then 方法失败');
            console.log(formatLog(logLines, callId, funcName));
            return;
        }
        var then_fn = then_ptr.readPointer();

        var napi_create_function = Module.findExportByName('qqnt.dll', 'napi_create_function');
        var napi_create_function_fn = new NativeFunction(napi_create_function, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
        var cb_name = Memory.allocUtf8String("onPromiseResolved");
        var cb_ptr = Memory.alloc(Process.pointerSize);

        // 1. 定义回调函数
        var onResolved = new NativeCallback(function (env_, cbinfo) {
            try {
                var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
                var napi_get_cb_info_fn = new NativeFunction(napi_get_cb_info, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                var argc_ptr = Memory.alloc(8); argc_ptr.writeU64(1);
                var argv_ptr = Memory.alloc(Process.pointerSize);
                napi_get_cb_info_fn(env_, cbinfo, argc_ptr, argv_ptr, ptr(0), ptr(0));
                var arg_ptr = argv_ptr.readPointer();

                // 2. 直接打印Promise resolve的值
                var lines = [];
                lines.push('[Promise] resolve:');
                printNapiValue(env_, arg_ptr, lines);
                lines.push('==== call end ====');

                // 取出主调用的logLines，合并Promise resolve内容
                let mainLogLines = callLogMap.get(callId);
                if (mainLogLines) {
                    lines.forEach(l => mainLogLines.push(l));
                    console.log(formatLog(mainLogLines, callId, funcName));
                    callLogMap.delete(callId);
                } else {
                    // fallback
                    console.log(formatLog(lines, callId, funcName));
                }
            } catch (e) {
                console.log('[Promise] resolve回调异常: ' + e);
            }
            if(globalNativeCallbacks.includes(onResolved)) {
                var index = globalNativeCallbacks.indexOf(onResolved);
                if (index !== -1) {
                    globalNativeCallbacks.splice(index, 1);
                }
            }
            return ptr(0);
        }, 'pointer', ['pointer', 'pointer']);

        // 3. 防止GC回收
        globalNativeCallbacks.push(onResolved);

        // 4. 创建JS function对象
        var status = napi_create_function_fn(env, cb_name, ptr(0), onResolved, ptr(0), cb_ptr);
        if (status !== 0) {
            logLines.push('[Promise] 创建回调函数失败: ' + status);
            logLines.push('==== call end ====');
            console.log(formatLog(logLines, callId, funcName));
            return;
        }

        // 5. 调用then
        var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
        var napi_call_function_fn = new NativeFunction(napi_call_function, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']);
        var argv = Memory.alloc(Process.pointerSize);
        argv.writePointer(cb_ptr.readPointer());
        var callStatus = napi_call_function_fn(env, promise, then_fn, 1, argv, ptr(0));
        if (callStatus !== 0) {
            logLines.push('[Promise] then调用失败: ' + callStatus);
            logLines.push('==== call end ====');
            console.log(formatLog(logLines, callId, funcName));
        }
    } catch (e) {
        logLines.push('[Promise] then 调用异常: ' + e);
        logLines.push('==== call end ====');
        console.log(formatLog(logLines, callId, funcName));
    }
}

function hookNapiFunc(name, offset) {
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    var funcAddr = baseAddr.add(offset);
    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            this.callId = getCallId();
            this.funcName = name;
            this.logLines = [];
            var env = args[0], info = args[1];
            this.env = env; // 保存env用于onLeave
            var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
            var napi_get_cb_info_fn = new NativeFunction(napi_get_cb_info, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
            var argc_ptr = Memory.alloc(8); argc_ptr.writeU64(8);
            var argv_ptr = Memory.alloc(Process.pointerSize * 8);
            var status = napi_get_cb_info_fn(env, info, argc_ptr, argv_ptr, ptr(0), ptr(0));
            if (status !== 0) {
                this.logLines.push(`[!] napi_get_cb_info failed: ` + status);
                callLogMap.set(this.callId, this.logLines);
                return;
            }
            var argc = argc_ptr.readU64();
            this.logLines.push(`参数量: ` + argc);
            for (var i = 0; i < argc; i++) {
                var arg_ptr = argv_ptr.add(i * Process.pointerSize).readPointer();
                printNapiValue(env, arg_ptr, this.logLines);
            }
            callLogMap.set(this.callId, this.logLines);
        },
        onLeave: function (retval) {
            let logLines = callLogMap.get(this.callId) || [];
            logLines.push('---- 返回值 ----');
            try {
                if (retval.isNull() || retval.isZero && retval.isZero()) {
                    logLines.push(`空返回`);
                    console.log(formatLog(logLines, this.callId, this.funcName));
                    callLogMap.delete(this.callId);
                } else {
                    if (isPromise(this.env, retval)) {
                        // 不立即输出，等Promise resolve后输出
                        callPromiseThen(this.env, retval, logLines, this.callId, this.funcName);
                    } else {
                        printNapiValue(this.env, retval, logLines);
                        console.log(formatLog(logLines, this.callId, this.funcName));
                        callLogMap.delete(this.callId);
                    }
                }
            } catch (e) {
                logLines.push('[!] 返回值序列化异常: ' + e);
                console.log(formatLog(logLines, this.callId, this.funcName));
                callLogMap.delete(this.callId);
            }
        }
    });
}

function main() {
    // 1. 先hook wrapper.node导出函数
    for (const [name, offset] of Object.entries(target_func_list)) {
        hookNapiFunc(name, offset);
    }

    // 2. hook on*相关 napi_get_named_property 和 napi_call_function
    // 记录所有on*函数的function指针及其名称
    const onFunctionMap = new Map();

    // hook napi_get_named_property
    (function() {
        const addr = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.env = args[0];
                this.namePtr = args[2];
                this.resultPtr = args[3];
                try {
                    this.propName = Memory.readUtf8String(this.namePtr);
                } catch {
                    this.propName = '';
                }
                this.shouldLog = this.propName && this.propName.startsWith('on');
            },
            onLeave(retval) {
                if (!this.shouldLog) return;
                if (retval.toInt32() === 0) {
                    try {
                        const funcPtr = this.resultPtr.readPointer();
                        if (!funcPtr.isNull()) {
                            onFunctionMap.set(funcPtr.toString(), this.propName);
                        }
                    } catch {}
                }
            }
        });
    })();

    // hook napi_call_function
    (function() {
        const addr = Module.findExportByName('qqnt.dll', 'napi_call_function');
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                const env = args[0];
                const func = args[2];
                const argc = args[3].toInt32();
                const argv = args[4];

                const funcKey = func.toString();
                const funcName = onFunctionMap.get(funcKey);

                if (funcName && funcName.startsWith('on')) {
                    let logLines = [];
                    logLines.push(`[on] 调用on*函数: ${funcName} @ ${func}`);
                    logLines.push(`参数数量: ${argc}`);
                    for (let i = 0; i < argc; i++) {
                        try {
                            const argPtr = argv.add(i * Process.pointerSize).readPointer();
                            logLines.push(`[arg] 参数${i}:`);
                            printNapiValue(env, argPtr, logLines);
                        } catch (e) {
                            logLines.push(`[arg] 参数${i}: <exception: ${e}>`);
                        }
                    }
                    console.log(formatLog(logLines, 'on_' + funcKey, funcName));
                }
            }
        });
    })();
}

main();