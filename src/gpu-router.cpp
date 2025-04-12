#include <array>
#include <vector>
#include <iostream>
#include <string>

#include <sycl/sycl.hpp>

#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <pcap.h> // Include libpcap
#include "dpc_common.hpp"


const size_t burst_size = 32;
#define PACKET_SIZE 64

int main() {
    sycl::queue q;

    std::cout << "Using device: " <<
        q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = 10;  // number of threads
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<std::vector<std::array<char, PACKET_SIZE>>> in_node{g,
        [&](tbb::flow_control& fc) -> std::vector<std::array<char, PACKET_SIZE>> {
            static pcap_t* handle = nullptr;
            static char errbuf[PCAP_ERRBUF_SIZE];

            if (!handle) {
                handle = pcap_open_offline("/root/keysight-challenge-2025/src/capture1.pcap", errbuf);
                if (!handle) {
                    std::cerr << "Error opening pcap file: " << errbuf << std::endl;
                    fc.stop();
                    return {};
                }
            }

            std::vector<std::array<char, PACKET_SIZE>> packets;
            struct pcap_pkthdr* header;
            const u_char* data;

            for (size_t i = 0; i < burst_size; ++i) {
                int ret = pcap_next_ex(handle, &header, &data);
                if (ret <= 0) { // No more packets or error
                    std::cout << "No more packets" << std::endl;
                    fc.stop();
                    break;
                }

                std::array<char, PACKET_SIZE> packet{};
                std::memcpy(packet.data(), data, std::min(static_cast<size_t>(header->caplen), static_cast<size_t>(PACKET_SIZE)));
                packets.push_back(packet);
            }

            std::cout << "Read " << packets.size() << " packets from capture1.pcap" << std::endl;
            return packets;
        }
    };

    // Packet inspection node
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>, int> inspect_packet_node {
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            // By including all the SYCL work in a {} block, we ensure
            // all SYCL tasks must complete before exiting the block
            {
                sycl::queue gpuQ(sycl::gpu_selector_v, dpc_common::exception_handler);

                std::cout << "Selected GPU Device Name: " <<
                    gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";

                gpuQ.submit([&](sycl::handler& h) {
                            auto compute = [=](auto i) {
                            // Process the packets
                            };

                            h.parallel_for(packets.size(), compute);
                        }
                    ).wait_and_throw();  // end of the commands for the SYCL queue

            }  // End of the scope for SYCL code; the queue has completed the work
 
            // Return the number of packets processed
            return packets.size();
        }};

    // construct graph
    tbb::flow::make_edge(in_node, inspect_packet_node);

    in_node.activate();
    g.wait_for_all();

    std::cout << "Done waiting" << std::endl;
}
