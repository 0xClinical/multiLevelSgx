#include "utils/timer.h"

void Timer::start(int interval, std::function<void()> func) {
    running_ = true;
    thread_ = std::thread([=]() {
        while (running_) {
            func();
            std::this_thread::sleep_for(std::chrono::minutes(interval));
        }
    });
}

void Timer::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

Timer::~Timer() {
    stop();
} 

