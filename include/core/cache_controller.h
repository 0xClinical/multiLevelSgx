#pragma once
#include "utils/timer.h"
#include "core/cluster.h"
#include <memory>

class CacheController {
public:
    CacheController(size_t refreshIntervalMinutes = 60) 
        : refreshInterval_(refreshIntervalMinutes) {
    }
    
    // 设置要管理的簇
    void setClusters(std::vector<Cluster>& clusters) {
        clusters_ref_ = &clusters;
    }
    
    // 添加自定义make_unique实现
    template<typename T, typename... Args>
    std::unique_ptr<T> make_unique(Args&&... args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }
    
    // 启动定期刷新
    void startRefreshTimer(size_t intervalSeconds) {
        refreshTimer_ = make_unique<Timer>();
        refreshTimer_->start(intervalSeconds, [this]() {
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
        if (!clusters_ref_) return;
        
        for (auto& cluster : *clusters_ref_) {
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
    std::vector<Cluster>* clusters_ref_{nullptr};  // 使用指针而不是存储簇
    std::unique_ptr<Timer> refreshTimer_;
    size_t refreshInterval_;
    std::function<void(Cluster&)> onClusterRefresh;  // 刷新回调
}; 