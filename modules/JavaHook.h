#ifndef JAVA_HOOK_H // !JAVA_HOOK_H
#define JAVA_HOOK_H

#include <jni.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/system_properties.h>
#include <android/log.h>

#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <unordered_set>

namespace android
{
#define Log(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "JavaHook", fmt __VA_OPT__(, ) __VA_ARGS__);

    namespace detail
    {
        static constexpr uint32_t kAccPublic = 0x0001;       // class, field, method, ic
        static constexpr uint32_t kAccPrivate = 0x0002;      // field, method, ic
        static constexpr uint32_t kAccProtected = 0x0004;    // field, method, ic
        static constexpr uint32_t kAccStatic = 0x0008;       // field, method, ic
        static constexpr uint32_t kAccFinal = 0x0010;        // class, field, method, ic
        static constexpr uint32_t kAccSynchronized = 0x0020; // method (only allowed on natives)
        static constexpr uint32_t kAccSuper = 0x0020;        // class (not used in dex)
        static constexpr uint32_t kAccVolatile = 0x0040;     // field
        static constexpr uint32_t kAccBridge = 0x0040;       // method (1.5)
        static constexpr uint32_t kAccTransient = 0x0080;    // field
        static constexpr uint32_t kAccVarargs = 0x0080;      // method (1.5)
        static constexpr uint32_t kAccNative = 0x0100;       // method
        static constexpr uint32_t kAccInterface = 0x0200;    // class, ic
        static constexpr uint32_t kAccAbstract = 0x0400;     // class, method, ic
        static constexpr uint32_t kAccStrict = 0x0800;       // method
        static constexpr uint32_t kAccSynthetic = 0x1000;    // class, field, method, ic
        static constexpr uint32_t kAccAnnotation = 0x2000;   // class, ic (1.5)
        static constexpr uint32_t kAccEnum = 0x4000;         // class, field, ic (1.5)

        static constexpr uint32_t kAccJavaFlagsMask = 0xffff; // bits set from Java sources (low 16)

        static constexpr uint32_t kAccConstructor = 0x00010000;          // method (dex only) <(cl)init>
        static constexpr uint32_t kAccDeclaredSynchronized = 0x00020000; // method (dex only)
        static constexpr uint32_t kAccClassIsProxy = 0x00040000;         // class  (dex only)
        // Set to indicate that the ArtMethod is obsolete and has a different DexCache + DexFile from its
        // declaring class. This flag may only be applied to methods.
        static constexpr uint32_t kAccObsoleteMethod = 0x00040000; // method (runtime)
        // Used by a method to denote that its execution does not need to go through slow path interpreter.
        static constexpr uint32_t kAccSkipAccessChecks = 0x00080000;    // method (runtime, not native)
        static constexpr uint32_t kAccSkipHiddenapiChecks = 0x00100000; // class (runtime)
        // Used by a class to denote that this class and any objects with this as a
        // declaring-class/super-class are to be considered obsolete, meaning they should not be used by.
        static constexpr uint32_t kAccObsoleteObject = 0x00200000; // class (runtime)
        // Set during boot image compilation to indicate that the class is
        // not initialized at compile tile and not in the list of preloaded classes.
        static constexpr uint32_t kAccInBootImageAndNotInPreloadedClasses = 0x00400000; // class (runtime)
        // This is set by the class linker during LinkInterfaceMethods. It is used by a method
        // to represent that it was copied from its declaring class into another class.
        // We need copies of the original method because the method may end up in different
        // places in classes vtables, and the vtable index is set in ArtMethod.method_index.
        //
        // Default methods copied to a sub-interface or a concrete class shall have this bit set.
        // Default conflict methods shall be marked as copied, abstract and default.
        // Miranda methods shall be marked as copied and abstract but not default.
        //
        // We do not have intrinsics for any default methods and therefore intrinsics are never
        // copied. We can therefore use a flag from the intrinsic flags range.
        static constexpr uint32_t kAccCopied = 0x01000000;  // method (runtime)
        static constexpr uint32_t kAccDefault = 0x00400000; // method (runtime)
        // Native method flags are set when linking the methods based on the presence of the
        // @dalvik.annotation.optimization.{Fast,Critical}Native annotations with build visibility.
        // Reuse the values of kAccSkipAccessChecks and kAccMiranda which are not used for native methods.
        static constexpr uint32_t kAccFastNative = 0x00080000;     // method (runtime; native only)
        static constexpr uint32_t kAccCriticalNative = 0x00100000; // method (runtime; native only)

        // Set by the JIT when clearing profiling infos to denote that a method was previously warm.
        static constexpr uint32_t kAccPreviouslyWarm = 0x00800000; // method (runtime)

        // Set by the verifier for a method we do not want the compiler to compile.
        static constexpr uint32_t kAccCompileDontBother = 0x02000000; // method (runtime)

        // Used in conjunction with kAccCompileDontBother to mark the method as pre compiled
        // by the JIT compiler. We are reusing the value of the kAccPreviouslyWarm flag which
        // is meaningless for other methods with kAccCompileDontBother as we do not collect
        // samples for such methods.
        static constexpr uint32_t kAccPreCompiled = 0x00800000; // method (runtime)
        static_assert(kAccPreCompiled == kAccPreviouslyWarm);

        // Set by the verifier for a method that could not be verified to follow structured locking.
        static constexpr uint32_t kAccMustCountLocks = 0x04000000; // method (runtime)

        // Set by the class linker for a method that has only one implementation for a
        // virtual call.
        static constexpr uint32_t kAccSingleImplementation = 0x08000000; // method (runtime)

        // Whether nterp can take a fast path when entering this method (runtime; non-native)
        static constexpr uint32_t kAccNterpEntryPointFastPathFlag = 0x00100000;
        // Set by the class linker to mark that a method does not have floating points
        // or longs in its shorty.
        static constexpr uint32_t kAccNterpInvokeFastPathFlag = 0x00200000; // method (runtime)

        static constexpr uint32_t kAccPublicApi = 0x10000000;       // field, method
        static constexpr uint32_t kAccCorePlatformApi = 0x20000000; // field, method

        // Non-intrinsics: Caches whether we can use fast-path in the interpreter invokes.
        // Intrinsics: These bits are part of the intrinsic ordinal.
        static constexpr uint32_t kAccFastInterpreterToInterpreterInvoke = 0x40000000; // method.

        // For methods which we'd like to share memory between zygote and apps.
        // Uses an intrinsic bit but that's OK as intrinsics are always in the boot image.
        static constexpr uint32_t kAccMemorySharedMethod = 0x40000000;

        // Set by the compiler driver when compiling boot classes with instrinsic methods.
        static constexpr uint32_t kAccIntrinsic = 0x80000000; // method (runtime)

        // Special runtime-only flags.
        // Interface and all its super-interfaces with default methods have been recursively initialized.
        static constexpr uint32_t kAccRecursivelyInitialized = 0x20000000;
        // Interface declares some default method.
        static constexpr uint32_t kAccHasDefaultMethod = 0x40000000;
        // class/ancestor overrides finalize()
        static constexpr uint32_t kAccClassIsFinalizable = 0x80000000;

        static constexpr uint32_t kAccHiddenapiBits = kAccPublicApi | kAccCorePlatformApi;

        // Continuous sequence of bits used to hold the ordinal of an intrinsic method. Flags
        // which overlap are not valid when kAccIntrinsic is set.
        static constexpr uint32_t kAccIntrinsicBits = kAccHiddenapiBits |
                                                      kAccSingleImplementation | kAccMustCountLocks | kAccCompileDontBother | kAccCopied |
                                                      kAccPreviouslyWarm | kAccMemorySharedMethod;

        // Valid (meaningful) bits for a field.
        static constexpr uint32_t kAccValidFieldFlags = kAccPublic | kAccPrivate | kAccProtected |
                                                        kAccStatic | kAccFinal | kAccVolatile | kAccTransient | kAccSynthetic | kAccEnum;

        // Valid (meaningful) bits for a method.
        static constexpr uint32_t kAccValidMethodFlags = kAccPublic | kAccPrivate | kAccProtected |
                                                         kAccStatic | kAccFinal | kAccSynchronized | kAccBridge | kAccVarargs | kAccNative |
                                                         kAccAbstract | kAccStrict | kAccSynthetic | kAccConstructor | kAccDeclaredSynchronized;
        static_assert(((kAccIntrinsic | kAccIntrinsicBits) & kAccValidMethodFlags) == 0,
                      "Intrinsic bits and valid dex file method access flags must not overlap.");

        // Valid (meaningful) bits for a class (not interface).
        // Note 1. These are positive bits. Other bits may have to be zero.
        // Note 2. Inner classes can expose more access flags to Java programs. That is handled by libcore.
        static constexpr uint32_t kAccValidClassFlags = kAccPublic | kAccFinal | kAccSuper |
                                                        kAccAbstract | kAccSynthetic | kAccEnum;

        // Valid (meaningful) bits for an interface.
        // Note 1. Annotations are interfaces.
        // Note 2. These are positive bits. Other bits may have to be zero.
        // Note 3. Inner classes can expose more access flags to Java programs. That is handled by libcore.
        static constexpr uint32_t kAccValidInterfaceFlags = kAccPublic | kAccInterface |
                                                            kAccAbstract | kAccSynthetic | kAccAnnotation;

        static constexpr uint32_t kAccVisibilityFlags = kAccPublic | kAccPrivate | kAccProtected;

        // Returns a human-readable version of the Java part of the access flags, e.g., "private static "
        // (note the trailing whitespace).
        std::string PrettyJavaAccessFlags(uint32_t accessFlags)
        {
            typedef struct FlagInfo
            {
                uint32_t flag;
                const char *info;
            } flag_info_t;

            flag_info_t checkFlags[] = {
                {kAccPublic, "public "},
                {kAccProtected, "protected "},
                {kAccPrivate, "private "},
                {kAccFinal, "final "},
                {kAccStatic, "static "},
                {kAccAbstract, "abstract "},
                {kAccInterface, "interface "},
                {kAccTransient, "transient "},
                {kAccVolatile, "volatile "},
                {kAccSynchronized, "synchronized "},
                {kAccNative, "native "},
                {kAccFastInterpreterToInterpreterInvoke, "fast_interpreter_to_interpreter_invoke "},
                {kAccSingleImplementation, "single_implementation "},
                {kAccNterpEntryPointFastPathFlag, "nterp_entry_point_fast_path_flag "},
                {kAccSkipAccessChecks, "skip_access_checks "},
                {kAccCompileDontBother, "compile_dont_bother "},
            };
            constexpr size_t flagsCount = sizeof(checkFlags) / sizeof(flag_info_t);

            std::string result;

            for (size_t i = 0; i < flagsCount; ++i)
            {
                if (0 != (checkFlags[i].flag & accessFlags))
                    result.append(checkFlags[i].info);
            }

            return result;
        }
    }

    class Module final
    {
    public:
        static std::vector<Module> EnumerateModules(const std::string_view &onlyTargetModule = "", void *onlyAddressModule = nullptr)
        {
            std::ifstream ifs("/proc/self/maps", std::ios::in | std::ios::binary);
            std::vector<Module> result;

            std::string line;
            while (std::getline(ifs, line))
            {
                size_t startPos = 0;
                size_t endPos = line.find('-');
                if (std::string::npos == endPos)
                    continue;
                auto baseString = line.substr(startPos, endPos - startPos);

                startPos = endPos + 1;
                endPos = line.find(' ', startPos);
                if (std::string::npos == endPos)
                    continue;
                auto endString = line.substr(startPos, endPos - startPos);

                startPos = line.find('/', startPos + 1);
                endPos = line.rfind(".so");
                if (std::string::npos == startPos || std::string::npos == endPos)
                    continue;
                auto fullPathString = line.substr(startPos, endPos - startPos + 3);

                auto begin = reinterpret_cast<ElfW(Ehdr) *>(std::stoull(baseString, 0, 16));
                if (ET_DYN != begin->e_type || 0 >= begin->e_phnum)
                    continue;

                result.emplace_back(
                    begin,
                    reinterpret_cast<uint8_t *>(std::stoull(endString, 0, 16)),
                    std::move(fullPathString));

                if (!onlyTargetModule.empty() && std::string::npos != line.find(onlyTargetModule))
                    break;
                if (nullptr != onlyAddressModule && (result.back().base < onlyAddressModule && result.back().end > onlyAddressModule))
                    break;
            }

            return result;
        }

        static Module FindModuleByName(const std::string_view &name)
        {
            auto modules = EnumerateModules(name);

            if (modules.empty())
                return {};
            if (modules.back().name != name)
                return {};

            return modules.back();
        }

        static Module FindModuleByAddress(void *address)
        {
            auto modules = EnumerateModules("", address);

            if (modules.empty())
                return {};
            if (modules.back().base > address || modules.back().end < address)
                return {};

            return modules.back();
        }

        template <typename method_t = void *>
        static method_t FindMethodGlobal(const std::string_view &name)
        {
            void *result = dlsym(RTLD_DEFAULT, name.data());

            if (nullptr == result)
                result = reinterpret_cast<method_t>(dlsym(dlopen("", RTLD_NOLOAD), name.data()));

            if (nullptr == result)
            {
                for (auto &module : EnumerateModules())
                {
                    if (nullptr != (result = module.FindMethodInternal(name)))
                        break;
                }
            }

            return reinterpret_cast<method_t>(result);
        }

    public:
        Module() {}
        Module(void *begin, void *end, std::string &&fullPath)
        {
            auto elfHeader = reinterpret_cast<ElfW(Ehdr) *>(begin);
            if (ET_DYN != elfHeader->e_type)
            {
                // Log("Error: module %s is not a shared library, begin:%p", name.data(), this->begin);
                return;
            }
            else if (0 >= elfHeader->e_phnum)
            {
                // Log("Error: module %s has no program header, begin:%p", name.data(), this->begin);
                return;
            }

            this->begin = reinterpret_cast<uint8_t *>(begin);
            this->end = reinterpret_cast<uint8_t *>(end);
            this->size = this->end - this->begin;
            this->name = fullPath.substr(fullPath.rfind('/', fullPath.size() - 3) + 1);
            this->path = fullPath.substr(0, fullPath.size() - (this->name.size() + 1));
            this->fullPath = std::move(fullPath);

            auto processHeaders = reinterpret_cast<ElfW(Phdr) *>(this->begin + elfHeader->e_phoff);
            auto dynamicHeader = processHeaders;
            auto minLoadSectionOffset = static_cast<ElfW(Addr)>(UINTPTR_MAX);
            for (size_t i = 0; i < elfHeader->e_phnum; ++i)
            {
                if (PT_LOAD == processHeaders[i].p_type && minLoadSectionOffset > processHeaders[i].p_vaddr)
                    minLoadSectionOffset = processHeaders[i].p_vaddr;
                if (PT_DYNAMIC == processHeaders[i].p_type)
                    dynamicHeader = processHeaders + i;
            }

            if (static_cast<ElfW(Addr)>(UINTPTR_MAX) == minLoadSectionOffset)
                base = this->begin;
            else
                base = this->begin - minLoadSectionOffset;

            auto dynamicSection = reinterpret_cast<ElfW(Dyn) *>(base + dynamicHeader->p_vaddr);
            while (DT_NULL != dynamicSection->d_tag)
            {
                switch (dynamicSection->d_tag)
                {
                case DT_STRSZ:
                    m_stringTableSize = dynamicSection->d_un.d_val;
                    break;
                case DT_STRTAB:
                    m_stringTable = reinterpret_cast<char *>(base + dynamicSection->d_un.d_ptr);
                    break;
                case DT_SYMTAB:
                    m_symbolTable = reinterpret_cast<ElfW(Sym) *>(base + dynamicSection->d_un.d_ptr);
                    break;
                case DT_HASH:
                    m_hashTable = reinterpret_cast<ElfW(Word) *>(base + dynamicSection->d_un.d_ptr);
                    m_hashTableType = DT_HASH;
                    break;
                case DT_GNU_HASH:
                    m_hashTable = reinterpret_cast<ElfW(Word) *>(base + dynamicSection->d_un.d_ptr);
                    m_hashTableType = DT_GNU_HASH;
                    break;
                default:
                    break;
                }

                ++dynamicSection;
            }

            if (0 == m_stringTableSize || nullptr == m_stringTable || nullptr == m_symbolTable || nullptr == m_hashTable)
            {
                // Log(
                //     "Error: module %s is incomplete shared library, stringTableSize:%d stringTable:%p symbolTable:%p hashTable:%p",
                //     name.data(),
                //     m_stringTableSize,
                //     m_stringTable,
                //     m_symbolTable,
                //     m_hashTable);

                base = nullptr;
            }
        }

        template <typename method_t = void *>
        method_t FindMethod(const std::string_view &name)
        {
            if (nullptr == m_handle)
                m_handle = dlopen(fullPath.data(), RTLD_LAZY);

            void *result = nullptr;
            if (nullptr != m_handle)
                result = dlsym(m_handle, name.data());

            if (nullptr == result)
                result = FindMethodInternal(name);

            return reinterpret_cast<method_t>(result);
        }

    private:
        uint32_t CalcNameHash(const char *name)
        {
            uint32_t cache, result = DT_HASH == m_hashTableType ? 0 : 5381;

            if (DT_HASH == m_hashTableType)
            {
                while (*name)
                {
                    result = (result << 4) + *name++;
                    cache = result & 0xf0000000;
                    result ^= cache;
                    result ^= cache >> 24;
                }
            }
            else
            {
                while (*name)
                    result += (result << 5) + *name++;
            }

            return result;
        }

        void *FindMethodInternal(const std::string_view &name)
        {
            if (nullptr == base)
                return nullptr;

            auto nameHash = CalcNameHash(name.data());
            auto numberOfBucket = m_hashTable[0];
            if (DT_HASH == m_hashTableType)
            {
                auto numberOfChain = m_hashTable[1];
                auto buckets = &m_hashTable[2];
                auto chains = &buckets[numberOfBucket];

                for (size_t symbolIndex = buckets[nameHash % numberOfBucket]; STN_UNDEF != symbolIndex; symbolIndex = chains[symbolIndex])
                {
                    if (name == std::string_view{m_stringTable + m_symbolTable[symbolIndex].st_name})
                        return base + m_symbolTable[symbolIndex].st_value;
                }
            }
            else
            {
                constexpr size_t bits = sizeof(uint32_t) == sizeof(void *) ? 32 : 64;
                auto symbolOffset = m_hashTable[1];
                auto bloomSize = m_hashTable[2];
                auto bloomShift = m_hashTable[3];
                auto blooms = reinterpret_cast<ElfW(Off) *>(&m_hashTable[4]);
                auto buckets = reinterpret_cast<ElfW(Word) *>(&blooms[bloomSize]);
                auto chains = &buckets[numberOfBucket];

                auto bloomValue = blooms[(nameHash / bits) % bloomSize];
                auto bloomMask = 0 | 1llu << (nameHash % bits) | 1llu << ((nameHash >> bloomShift) % bits);
                if (bloomMask != (bloomValue & bloomMask))
                    return nullptr; // symbol missing

                auto symbolIndex = buckets[nameHash % numberOfBucket];
                if (symbolIndex < symbolOffset)
                    return nullptr; // no symbol

                for (;;)
                {
                    auto hash = chains[symbolIndex - symbolOffset];

                    if ((1 | nameHash) == (1 | hash) && name == std::string_view{m_stringTable + m_symbolTable[symbolIndex].st_name})
                        return base + m_symbolTable[symbolIndex].st_value;

                    if (0 != (hash & 1))
                        break;

                    ++symbolIndex;
                }
            }

            return nullptr;
        }

    public:
        uint8_t *base = nullptr;
        uint8_t *begin = nullptr;
        uint8_t *end = nullptr;
        size_t size = 0;
        std::string name;
        std::string path;
        std::string fullPath;

    private:
        void *m_handle = nullptr;

        ElfW(Sym) *m_symbolTable = nullptr;
        char *m_stringTable = nullptr;
        size_t m_stringTableSize = 0;
        ElfW(Word) *m_hashTable = nullptr;
        size_t m_hashTableType = DT_HASH;
    };

    class Runtime final
    {
    public:
        class JavaEnvironment
        {
        public:
            ~JavaEnvironment()
            {
                if (nullptr != vm && m_attachedThreads.contains(std::this_thread::get_id()))
                {
                    if (JNI_OK == vm->DetachCurrentThread())
                        m_attachedThreads.erase(std::this_thread::get_id());
                    else
                        Log("Error: vm->DetachCurrentThread() failed.");
                }
            }
            JavaEnvironment() {}
            JavaEnvironment(JavaVM *vm) : vm(vm)
            {
                if (JNI_OK != vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6))
                    Log("Error: vm->GetEnv failed.");

                if (nullptr == env)
                {
                    if (JNI_OK != vm->AttachCurrentThread(&env, nullptr))
                        m_attachedThreads.insert(std::this_thread::get_id());
                    else
                        Log("Error: vm->AttachCurrentThread failed.");
                }
            }
            JavaEnvironment(const JavaEnvironment &other) = delete;
            JavaEnvironment &operator=(const JavaEnvironment &other) = delete;

            JNIEnv *operator->()
            {
                return env;
            }

        public:
            JavaVM *vm;
            JNIEnv *env;

        private:
            static std::unordered_set<std::thread::id> m_attachedThreads;
        };

    public:
        static Runtime &Instance()
        {
            static Runtime runtime;

            return runtime;
        }

        JavaEnvironment GetEnv()
        {
            if (nullptr == vm)
            {
                Log("Error: vm is nullptr.");
                return {};
            }

            return {vm};
        }

    private:
        ~Runtime() {}
        Runtime()
        {
            char propertyStringBuffer[PROP_VALUE_MAX]{};

            auto length = __system_property_get("ro.build.version.codename", propertyStringBuffer);
            if (0 != length)
                codename.assign(propertyStringBuffer, length);

            length = __system_property_get("ro.build.version.release", propertyStringBuffer);
            if (0 != length)
                release = std::stoi(std::string{propertyStringBuffer, propertyStringBuffer + length});

            length = __system_property_get("ro.build.version.sdk", propertyStringBuffer);
            if (0 != length)
                sdk = std::stoi(std::string{propertyStringBuffer, propertyStringBuffer + length});

            m_libart = Module::FindModuleByName("libart.so");
            auto PJNI_GetCreatedJavaVMs = m_libart.FindMethod<jint (*)(JavaVM **, jsize, jsize *)>("JNI_GetCreatedJavaVMs");
            if (nullptr == PJNI_GetCreatedJavaVMs)
            {
                Log("Error: the function JNI_GetCreatedJavaVMs is not found.");
                return;
            }

            jsize vmCount = 0;
            if (JNI_OK != PJNI_GetCreatedJavaVMs(&vm, 1, &vmCount))
            {
                Log("Error: JNI_GetCreatedJavaVMs requested version is not supported.");
            }
            else if (0 == vmCount)
                Log("Error: JNI_GetCreatedJavaVMs cannot find JavaVMs.");
        }

    public:
        std::string codename;
        uint32_t release;
        uint32_t sdk;

        JavaVM *vm;

    private:
        JNIEnv *m_env = nullptr;
        Module m_libart;
    };

    class ArtMethod final
    {
    public:
        ~ArtMethod() {}
        ArtMethod(jmethodID methodId)
        {
            if (nullptr == methodId)
                return;

            if (0 == m_accessFlagsOffset || 0 == m_quickCodeOffset)
            {
                auto &runtime = Runtime::Instance();

                if (23 > runtime.sdk)
                {
                    Log("Error: unsupported sdk version %d", runtime.sdk);
                    return;
                }

                if (24 <= runtime.sdk)
                    m_accessFlagsOffset = 4;
                else if (23 <= runtime.sdk)
                    m_accessFlagsOffset = 12;

                auto libart = Module::FindModuleByName("libart.so");
                if (nullptr == libart.begin)
                {
                    Log("Error: cannot find libart.so");
                    return;
                }

                auto searchPointer = reinterpret_cast<uint8_t *>(methodId);
                for (size_t offset = 0; offset < 64; offset += 4)
                {
                    auto stubEntry = *reinterpret_cast<void **>(searchPointer + offset);

                    if (libart.begin < stubEntry && libart.end > stubEntry)
                    {
                        m_quickCodeOffset = offset;
                        break;
                    }
                }
            }

            if (0 == m_accessFlagsOffset || 0 == m_quickCodeOffset)
            {
                Log("Error: cannot initialization ArtMethod %p", methodId);
                return;
            }

            auto basePointer = reinterpret_cast<uint8_t *>(methodId);
            m_accessFlagsPointer = reinterpret_cast<uint32_t *>(basePointer + m_accessFlagsOffset);
            m_quickCodePointer = reinterpret_cast<void **>(basePointer + m_quickCodeOffset);

            m_initialized = true;
        }

        uint32_t GetAccessFlags() const
        {
            return *m_accessFlagsPointer;
        }
        void SetAccessFlags(uint32_t accessFlags)
        {
            *m_accessFlagsPointer = accessFlags;
        }

        void *GetEntryPointFromQuickCompiledCode() const
        {
            return *m_quickCodePointer;
        }
        void SetEntryPointFromQuickCompiledCode(void *code)
        {
            *m_quickCodePointer = code;
        }

        std::string PrettyJavaAccessFlags() const
        {
            return detail::PrettyJavaAccessFlags(*m_accessFlagsPointer);
        }

        bool IsValid() const
        {
            return m_initialized;
        }

        operator bool() const
        {
            return m_initialized;
        }

    private:
        static size_t m_accessFlagsOffset;
        static size_t m_quickCodeOffset;

        bool m_initialized = false;
        uint32_t *m_accessFlagsPointer = nullptr;
        void **m_quickCodePointer = nullptr;
    };

    class JavaHook final
    {
    public:
        using EntryPointDispatcher = void *(*)(jmethodID *thisMethod, void **args, size_t argsSize, void *artThreadSelf, jvalue *result, const char *shorty);

    public:
        ~JavaHook() {}
        JavaHook() : m_method(nullptr) {}
        JavaHook(jmethodID methodId)
            : m_method(methodId)
        {
            if (!m_method)
            {
                Log("Error: hook method %p failed.", methodId);
                return;
            }

            m_originalAccessFlags = m_method.GetAccessFlags();
            m_originalQuickCode = m_method.GetEntryPointFromQuickCompiledCode();
        }
        JavaHook(jclass clazz, const std::string_view &methodName, const std::string_view &methodSignature)
            : JavaHook(Runtime::Instance().GetEnv()->GetMethodID(clazz, methodName.data(), methodSignature.data()))
        {
        }
        JavaHook(const std::string_view &classPath, const std::string_view &methodName, const std::string_view &methodSignature)
            : JavaHook(Runtime::Instance().GetEnv()->FindClass(classPath.data()), methodName, methodSignature)
        {
        }

        bool Enable(void *customDispather)
        {
            if (!m_method)
                return false;

            constexpr auto removeFlags = ~(detail::kAccFastInterpreterToInterpreterInvoke | detail::kAccSingleImplementation | detail::kAccNterpEntryPointFastPathFlag | detail::kAccSkipAccessChecks);

            m_method.SetAccessFlags((m_originalAccessFlags & removeFlags) | detail::kAccCompileDontBother | detail::kAccNative);
            m_method.SetEntryPointFromQuickCompiledCode(customDispather);

            return true;
        }
        bool Enable(EntryPointDispatcher customDispather)
        {
            return Enable(reinterpret_cast<void *>(customDispather));
        }

        bool Disable()
        {
            if (!m_method)
                return false;

            m_method.SetAccessFlags(m_originalAccessFlags);
            m_method.SetEntryPointFromQuickCompiledCode(m_originalQuickCode);

            return true;
        }

    private:
        ArtMethod m_method;

        uint32_t m_originalAccessFlags;
        void *m_originalQuickCode;
    };

    std::unordered_set<std::thread::id> Runtime::JavaEnvironment::m_attachedThreads{};
    size_t ArtMethod::m_accessFlagsOffset = 0;
    size_t ArtMethod::m_quickCodeOffset = 0;
}

#endif // !JAVA_HOOK_H