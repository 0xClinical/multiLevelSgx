#pragma once
#include <thread>
#include <functional>
#include <atomic>
#include <chrono>

class Timer {
public:
    Timer() : running_(false) {}
    
    void start(int interval, std::function<void()> func);
    void stop();
    
    ~Timer();

private:
    std::thread thread_;
    std::atomic<bool> running_;
}; 