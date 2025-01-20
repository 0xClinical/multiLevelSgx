#pragma once
#include "utils/timer.h"
#include "core/cluster.h"
#include <memory>

class CacheController {
public:
    CacheController(size_t refreshIntervalMinutes = 30) 
        : refreshInterval_(refreshIntervalMinutes) {
        startRefreshTimer();
    }
    
    // 启动定期刷新
    void startRefreshTimer() {
        refreshTimer_ = std::make_unique<Timer>();
        refreshTimer_->start(refreshInterval_, [this]() {
            refreshClusters();
        });
    }
    
    // 停止定期刷新
    void stopRefreshTimer() {
        if (refreshTimer_) {
            refreshTimer_->stop();
        }
    }
    
    // 刷新所有簇
    void refreshClusters() {
        for (auto& cluster : clusters_) {
            if (cluster.capacity() > 0) {  // 只刷新非空簇
                onClusterRefresh(cluster);  // 触发回调
            }
        }
    }
    
    // 设置刷新回调
    void setRefreshCallback(std::function<void(Cluster&)> callback) {
        onClusterRefresh = std::move(callback);
    }
    
    ~CacheController() {
        stopRefreshTimer();
    }

private:
    std::vector<Cluster> clusters_;
    std::unique_ptr<Timer> refreshTimer_;
    size_t refreshInterval_;
    std::function<void(Cluster&)> onClusterRefresh;  // 刷新回调
}; 