//
//  ring_buffer_s.h
//
//  Created by Pierre


#ifndef ring_buffer_s_h
#define ring_buffer_s_h

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <mutex>

#define USE_PIPE  0x00000001

class ring_buffer_s
{
public:
    ring_buffer_s(ring_buffer_s &&) = delete;
    ring_buffer_s& operator=(ring_buffer_s&& other) = delete;
    ring_buffer_s(const ring_buffer_s &) = delete;
    ring_buffer_s& operator=(const ring_buffer_s& other) = delete;

    ring_buffer_s(const size_t capacity)
    : front_(0)
    , rear_(0)
    , size_(0)
    , capacity_(capacity)
    {
        data_ = new uint8_t[capacity];
        raw_fds[0] = -1;
        raw_fds[1] = -1;
    }
    ring_buffer_s(const size_t capacity, int mode)
    : ring_buffer_s(capacity)
    {
        mode_ = mode;
        if((mode_ & USE_PIPE) == USE_PIPE) {
            pipe(raw_fds);
        }
    }

    virtual ~ring_buffer_s()
    {
        if(data_)
            delete[] data_;
        close();
    }
    
    int getPipeReadFD() {
        return raw_fds[0];
    }
    
    int getPipeWriteFD() {
        return raw_fds[1];
    }
    
    void close() {
        if(closed_)
            return;
        std::unique_lock<std::mutex> lock(mut_read_write_);
        if(!closed_) {
            closed_ = true;
            if((mode_ & USE_PIPE) == USE_PIPE) {
                ::close(raw_fds[0]);
                ::close(raw_fds[1]);
            }
        }
        condition_.notify_all();
    }
    
    size_t available()
    {
        std::unique_lock<std::mutex> lock(mut_read_write_);
        if((mode_ & USE_PIPE) == USE_PIPE) {
            int count = 0;
            if(ioctl(raw_fds[0], FIONREAD, &count) >= 0 && count > 0)
                return count;
            return 0;
        }
        return size_;
    }
    
    ssize_t write(const void *data, const size_t bytes)
    {
        if((mode_ & USE_PIPE) == USE_PIPE) {
            return ::write(raw_fds[1], data, bytes);
        }

        if (bytes == 0) return 0;
        // 通过互斥量保证任意时刻，至多只有一个线程在写数据。
        std::unique_lock<std::mutex> lock(mut_read_write_);
        const auto capacity = capacity_;
        size_t bytes_to_write = 0;
        while(true) {
            if(closed_)
                return -1;
            bytes_to_write = std::min(bytes, capacity - size_);
            if (bytes_to_write == 0)
                condition_.wait(lock);
            else
                break;
        }
        
        // 一次性写入
        if (bytes_to_write <= capacity - rear_)
        {
            memcpy(data_ + rear_, data, bytes_to_write);
            rear_ += bytes_to_write;
            if (rear_ == capacity) rear_ = 0;
        }
        // 分两步进行
        else
        {
            const auto size_1 = capacity - rear_;
            memcpy(data_ + rear_, data, size_1);
            const auto size_2 = bytes_to_write - size_1;
            memcpy(data_, static_cast<const uint8_t*>(data) + size_1, size_2);
            rear_ = size_2;
        }
        size_ += bytes_to_write;
        if(read_wait_flag_) {
            condition_.notify_all();
        }
        return bytes_to_write;
    }
    
    ssize_t read(void *data, const size_t bytes)
    {
        return read(data, bytes, NULL);
    }
    
    ssize_t read(void *data, const size_t bytes, ssize_t *available)
    {
        if((mode_ & USE_PIPE) == USE_PIPE) {
            return ::read(raw_fds[0], data, bytes);
        }

        if (bytes == 0) return 0;
        // 通过互斥量保证任意时刻，至多只有一个线程在读数据。
        std::unique_lock<std::mutex> lock(mut_read_write_);
        const auto capacity = capacity_;
        size_t bytes_to_read = 0;
        while(true) {
            bytes_to_read = std::min(bytes, size_);
            if (bytes_to_read == 0) {
                if(closed_)
                    return -1;
                read_wait_flag_++;
                condition_.wait(lock);
                read_wait_flag_--;
            }
            else
                break;
        }
        
        // 一次性读取
        if (bytes_to_read <= capacity - front_)
        {
            memcpy(data, data_ + front_, bytes_to_read);
            front_ += bytes_to_read;
            if (front_ == capacity) front_ = 0;
        }
        // 分两步进行
        else
        {
            const auto size_1 = capacity - front_;
            memcpy(data, data_ + front_, size_1);
            const auto size_2 = bytes_to_read - size_1;
            memcpy(static_cast<uint8_t*>(data) + size_1, data_, size_2);
            front_ = size_2;
        }
        size_ -= bytes_to_read;
        if(available)
            *available = size_;
        if(size_ == 0) { // 如果读取线程不工作，该条件会导致写线程阻塞，但该条件效率更高
            condition_.notify_all();
        }
        return bytes_to_read;
    }
    
private:
    int raw_fds[2];

    size_t front_, rear_, size_, capacity_;
    uint8_t *data_ = NULL;
    std::mutex mut_read_write_;
    bool closed_ = false;
    int read_wait_flag_ = 0;
    int mode_ = 0;

    std::condition_variable condition_;
    
};

#endif /* ring_buffer_s_h */
