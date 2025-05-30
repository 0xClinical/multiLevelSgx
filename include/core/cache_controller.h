#pragma once
#include "utils/timer.h"
#include "core/cluster.h"
#include <memory>

class CacheController {
public:
    CacheController(size_t refreshIntervalMinutes = 60) 
        : refreshInterval_(refreshIntervalMinutes) {
    }
    
   
    void setClusters(std::vector<Cluster>& clusters) {
        clusters_ref_ = &clusters;
    }
    
  
    template<typename T, typename... Args>
    std::unique_ptr<T> make_unique(Args&&... args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }
    
 
    void startRefreshTimer(size_t intervalSeconds) {
        refreshTimer_ = make_unique<Timer>();
        refreshTimer_->start(intervalSeconds, [this]() {
            refreshClusters();
        });
    }
    

    void stopRefreshTimer() {
        if (refreshTimer_) {
            refreshTimer_->stop();
        }
    }
    
 
    void refreshClusters() {
        if (!clusters_ref_) return;
        
        for (auto& cluster : *clusters_ref_) {
            if (cluster.capacity() > 0) {  
                onClusterRefresh(cluster);  
            }
        }
    }
    
  
    void setRefreshCallback(std::function<void(Cluster&)> callback) {
        onClusterRefresh = std::move(callback);
    }
    
    ~CacheController() {
        stopRefreshTimer();
    }

private:
    std::vector<Cluster>* clusters_ref_{nullptr};  
    std::unique_ptr<Timer> refreshTimer_;
    size_t refreshInterval_;
    std::function<void(Cluster&)> onClusterRefresh;  
}; 