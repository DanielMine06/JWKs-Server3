package com.daniel.Main;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

public class TimeWindowRateLimiter {
    private static final long WINDOW_SIZE = 1; // 1 second
    private static final int MAX_REQUESTS = 10; // Limit to 10 requests per window

 // private final ConcurrentHashMap<String, Long> requestTimestamps = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<Long> requestTimestmaps = new ConcurrentLinkedQueue<Long>();
    
    
    public boolean allowRequest() {
        long currentTime = System.currentTimeMillis();
        long windowStart = currentTime - TimeUnit.SECONDS.toMillis(WINDOW_SIZE);

        // Remove timestamps that are outside the time window
        while(!requestTimestmaps.isEmpty() && requestTimestmaps.peek() < windowStart) {
        	requestTimestmaps.poll();
        }
        
        // Count the number of requests within the time window for the given IP address
        long requestCount = requestTimestmaps.size();

        // If the request count is below the rate limit, allow the request
        if (requestCount < MAX_REQUESTS) {
        	requestTimestmaps.add( currentTime);
            return true;
        } else {
        //	requestTimestmaps.add( currentTime);

            return false; // Rate limit exceeded
        }
    }
}