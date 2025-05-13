#pragma once
#include <functional>
#include <atomic>


class Timer {
public:
    Timer() : running_(false) {}
    
    void start(int interval, std::function<void()> func) {
        running_ = true;
        interval_ = interval;
        func_ = func;
    }
    
    // 手动更新定时器
    void update() {
        if (running_) {
            func_();
        }
    }
    
    void stop() {
        running_ = false;
    }
    
    ~Timer() {
        stop();
    }

private:
    std::atomic<bool> running_;
    int interval_;
    std::function<void()> func_;
}; 