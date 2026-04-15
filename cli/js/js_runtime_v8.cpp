#include <v8.h>
#include <libplatform/libplatform.h>

#include <iostream>
#include <string>
#include <memory>

static std::unique_ptr<v8::Platform> g_platform;
static v8::Isolate* g_isolate = nullptr;

// MARS.log(msg)
void MarsLogCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
    if (args.Length() < 1) return;

    v8::String::Utf8Value msg(args.GetIsolate(), args[0]);
    if (*msg) {
        std::cout << "[MARS] " << *msg << std::endl;
    }
}


// INIT V8
void js_v8_init() {
    if (g_isolate) return;

    v8::V8::InitializeICUDefaultLocation(nullptr);
    v8::V8::InitializeExternalStartupData(nullptr);

    g_platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(g_platform.get());
    v8::V8::Initialize();

    v8::Isolate::CreateParams params;
    params.array_buffer_allocator =
        v8::ArrayBuffer::Allocator::NewDefaultAllocator();

    g_isolate = v8::Isolate::New(params);
}


// EXECUTE JS
std::string js_eval_string(const std::string& code) {
    js_v8_init();

    v8::Isolate::Scope isolate_scope(g_isolate);
    v8::HandleScope handle_scope(g_isolate);

    v8::Local<v8::Context> context = v8::Context::New(g_isolate);
    v8::Context::Scope context_scope(context);

    // CREATE MARS OBJECT
    v8::Local<v8::Object> mars = v8::Object::New(g_isolate);

    mars->Set(
        context,
        v8::String::NewFromUtf8(g_isolate, "log").ToLocalChecked(),
        v8::Function::New(
            context,
            MarsLogCallback
        ).ToLocalChecked()
    ).Check();

    context->Global()->Set(
        context,
        v8::String::NewFromUtf8(g_isolate, "MARS").ToLocalChecked(),
        mars
    ).Check();

    // RUN SCRIPT
    v8::TryCatch try_catch(g_isolate);

    v8::Local<v8::String> source;
    if (!v8::String::NewFromUtf8(
            g_isolate,
            code.c_str(),
            v8::NewStringType::kNormal
        ).ToLocal(&source)) {
        return "JS string error";
    }

    v8::Local<v8::Script> script;
    if (!v8::Script::Compile(context, source).ToLocal(&script)) {
        v8::String::Utf8Value err(g_isolate, try_catch.Exception());
        return *err ? *err : "compile error";
    }

    v8::Local<v8::Value> result;
    if (!script->Run(context).ToLocal(&result)) {
        v8::String::Utf8Value err(g_isolate, try_catch.Exception());
        return *err ? *err : "runtime error";
    }

    v8::String::Utf8Value utf8(g_isolate, result);
    return *utf8 ? *utf8 : "";
}
