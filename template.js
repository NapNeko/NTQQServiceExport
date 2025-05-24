
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

const globalNativeCallbacks = [];

function callPromiseThen(env, promise, logLines) {
    try {
        var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        var then_name = Memory.allocUtf8String("then");
        var then_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, promise, then_name, then_ptr) !== 0) {
            logLines.push('[Promise] 获取 then 方法失败');
            console.log(logLines.join('\n'));
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
                console.log(lines.join('\n'));
            } catch (e) {
                console.log('[Promise] resolve回调异常: ' + e);
            }
            if(globalNativeCallbacks.includes(onResolved)) {
                // 3. 从全局回调列表中移除，防止内存泄漏
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
            console.log(logLines.join('\n'));
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
            console.log(logLines.join('\n'));
        }
    } catch (e) {
        logLines.push('[Promise] then 调用异常: ' + e);
        logLines.push('==== call end ====');
        console.log(logLines.join('\n'));
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
            this.logLines = [];
            this.logLines.push(`==== ${name} call ====`);
            var env = args[0], info = args[1];
            this.env = env; // 保存env用于onLeave
            var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
            var napi_get_cb_info_fn = new NativeFunction(napi_get_cb_info, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
            var argc_ptr = Memory.alloc(8); argc_ptr.writeU64(8);
            var argv_ptr = Memory.alloc(Process.pointerSize * 8);
            var status = napi_get_cb_info_fn(env, info, argc_ptr, argv_ptr, ptr(0), ptr(0));
            if (status !== 0) {
                this.logLines.push(`[${name}] napi_get_cb_info failed: ` + status);
                console.log(this.logLines.join('\n'));
                return;
            }
            var argc = argc_ptr.readU64();
            this.logLines.push(`Function: ${name} Argc: ` + argc);
            for (var i = 0; i < argc; i++) {
                var arg_ptr = argv_ptr.add(i * Process.pointerSize).readPointer();
                printNapiValue(env, arg_ptr, this.logLines);
            }
        },
        onLeave: function (retval) {
            this.logLines.push('---- 返回值 ----');
            try {
                // 判空
                if (retval.isNull() || retval.isZero && retval.isZero()) {
                    this.logLines.push('[!] 返回值为 NULL 或 0，无法序列化');
                    this.logLines.push(`==== call end ====`);
                    console.log(this.logLines.join('\n'));
                } else {
                    if (isPromise(this.env, retval)) {
                        this.logLines.push('[Promise] 返回值为Promise，等待resolve...');
                        callPromiseThen(this.env, retval, this.logLines);
                    } else {
                        printNapiValue(this.env, retval, this.logLines);
                        this.logLines.push(`==== call end ====`);
                        console.log(this.logLines.join('\n'));
                    }
                }

            } catch (e) {
                this.logLines.push('[!] 返回值序列化异常: ' + e);
                this.logLines.push(`==== call end ====`);
                console.log(this.logLines.join('\n'));
            }
        }
    });
}

function main() {
    for (const [name, offset] of Object.entries(target_func_list)) {
        hookNapiFunc(name, offset);
    }
}

main();