#include "utils/RefBase.h"
#include "utils/String16.h"
#include "utils/String8.h"
#include "utils/StrongPointer.h"

#include <atomic>
#include <cstdint>

namespace android {

namespace {
constexpr int32_t kObjectLifetimeStrong = 0;
constexpr int32_t kObjectLifetimeWeak = 1;
constexpr int32_t kObjectLifetimeMask = 1;
constexpr uint32_t kFirstIncStrong = 1;

[[noreturn]] void stubRefBaseAbort() {
    __builtin_trap();
}
}

class RefBase::weakref_impl final : public RefBase::weakref_type {
public:
    explicit weakref_impl(RefBase *owner)
        : owner_(owner), strong_count_(0), weak_count_(1), lifetime_flags_(kObjectLifetimeStrong) {}

    RefBase *owner() const { return owner_.load(std::memory_order_acquire); }

    void clearOwner() { owner_.store(nullptr, std::memory_order_release); }

    std::atomic<RefBase *> owner_;
    std::atomic<int32_t> strong_count_;
    std::atomic<int32_t> weak_count_;
    std::atomic<int32_t> lifetime_flags_;
};

void RefBase::incStrong(const void *id) const {
    auto *refs = mRefs;
    refs->incWeak(id);
    const int32_t previous = refs->strong_count_.fetch_add(1, std::memory_order_acq_rel);
    if (previous == 0) {
        const_cast<RefBase *>(this)->onFirstRef();
    }
}

void RefBase::incStrongRequireStrong(const void *id) const {
    auto *refs = mRefs;
    int32_t current = refs->strong_count_.load(std::memory_order_acquire);
    while (current > 0) {
        if (
            refs->strong_count_.compare_exchange_weak(
                current,
                current + 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            )
        ) {
            refs->incWeak(id);
            return;
        }
    }
    stubRefBaseAbort();
}

void RefBase::decStrong(const void *id) const {
    auto *refs = mRefs;
    const int32_t previous = refs->strong_count_.fetch_sub(1, std::memory_order_acq_rel);
    if (previous <= 0) {
        stubRefBaseAbort();
    }
    if (previous == 1) {
        auto *owner = const_cast<RefBase *>(this);
        owner->onLastStrongRef(id);
        if ((refs->lifetime_flags_.load(std::memory_order_acquire) & kObjectLifetimeMask) == kObjectLifetimeStrong) {
            refs->clearOwner();
            delete owner;
        }
    }
    refs->decWeak(id);
}

void RefBase::forceIncStrong(const void *id) const {
    incStrong(id);
}

int32_t RefBase::getStrongCount() const {
    return mRefs->strong_count_.load(std::memory_order_acquire);
}

RefBase *RefBase::weakref_type::refBase() const {
    return static_cast<const weakref_impl *>(this)->owner();
}

void RefBase::weakref_type::incWeak(const void *id) {
    (void)id;
    static_cast<weakref_impl *>(this)->weak_count_.fetch_add(1, std::memory_order_acq_rel);
}

void RefBase::weakref_type::incWeakRequireWeak(const void *id) {
    (void)id;
    auto *refs = static_cast<weakref_impl *>(this);
    int32_t current = refs->weak_count_.load(std::memory_order_acquire);
    while (current > 0) {
        if (
            refs->weak_count_.compare_exchange_weak(
                current,
                current + 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            )
        ) {
            return;
        }
    }
    stubRefBaseAbort();
}

void RefBase::weakref_type::decWeak(const void *id) {
    auto *refs = static_cast<weakref_impl *>(this);
    const int32_t previous = refs->weak_count_.fetch_sub(1, std::memory_order_acq_rel);
    if (previous <= 0) {
        stubRefBaseAbort();
    }
    if (previous != 1) {
        return;
    }

    RefBase *owner = refs->owner();
    const int32_t lifetime = refs->lifetime_flags_.load(std::memory_order_acquire);
    if (owner != nullptr && (lifetime & kObjectLifetimeMask) == kObjectLifetimeWeak) {
        refs->clearOwner();
        owner->onLastWeakRef(id);
        delete owner;
    }
    delete refs;
}

bool RefBase::weakref_type::attemptIncStrong(const void *id) {
    auto *refs = static_cast<weakref_impl *>(this);
    while (true) {
        int32_t current = refs->strong_count_.load(std::memory_order_acquire);
        if (current > 0) {
            if (
                refs->strong_count_.compare_exchange_weak(
                    current,
                    current + 1,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire
                )
            ) {
                refs->incWeak(id);
                return true;
            }
            continue;
        }

        if ((refs->lifetime_flags_.load(std::memory_order_acquire) & kObjectLifetimeMask) != kObjectLifetimeWeak) {
            return false;
        }

        RefBase *owner = refs->owner();
        if (owner == nullptr) {
            return false;
        }
        if (!owner->onIncStrongAttempted(kFirstIncStrong, id)) {
            return false;
        }

        current = 0;
        if (
            refs->strong_count_.compare_exchange_strong(
                current,
                1,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            )
        ) {
            refs->incWeak(id);
            return true;
        }
    }
}

bool RefBase::weakref_type::attemptIncWeak(const void *id) {
    (void)id;
    auto *refs = static_cast<weakref_impl *>(this);
    int32_t current = refs->weak_count_.load(std::memory_order_acquire);
    while (current > 0) {
        if (
            refs->weak_count_.compare_exchange_weak(
                current,
                current + 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            )
        ) {
            return true;
        }
    }
    return false;
}

int32_t RefBase::weakref_type::getWeakCount() const {
    return static_cast<const weakref_impl *>(this)->weak_count_.load(std::memory_order_acquire);
}

void RefBase::weakref_type::printRefs() const {}

void RefBase::weakref_type::trackMe(bool enable, bool retain) {
    (void)enable;
    (void)retain;
}

RefBase::weakref_type *RefBase::createWeak(const void *id) const {
    mRefs->incWeak(id);
    return mRefs;
}

RefBase::weakref_type *RefBase::getWeakRefs() const {
    return mRefs;
}

RefBase::RefBase() : mRefs(new weakref_impl(this)) {}

RefBase::~RefBase() {
    mRefs->clearOwner();
}

void RefBase::extendObjectLifetime(int32_t mode) {
    mRefs->lifetime_flags_.store(mode, std::memory_order_release);
}

void RefBase::onFirstRef() {}

void RefBase::onLastStrongRef(const void *id) {
    (void)id;
}

bool RefBase::onIncStrongAttempted(uint32_t flags, const void *id) {
    (void)flags;
    (void)id;
    return false;
}

void RefBase::onLastWeakRef(const void *id) {
    (void)id;
}

void sp_report_race() {}

String8::String8() {}

String16::String16() {}

String16::String16(const String16 &o) {
    (void)o;
}

String16::String16(String16 &&o) noexcept {
    (void)o;
}

String16::String16(const char *o) {
    (void)o;
}

String16::~String16() {}

}
