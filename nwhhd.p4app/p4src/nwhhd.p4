/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

// These values must be same as the values in the commands.txt
#define CPU_MIRROR_SESSION_ID 250
#define MIN 1
#define CM_ROW 30 
#define THETA 5
#define EPSILON_INVERSE 10000 
#define K 10
#define W 3
#define SAMPLELIST_SIZE 10
#define MAXIMUM_PACKETS 1 

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop() {
    drop();
}

//
header_type intrinsic_metadata_t {
    fields {
            ingress_global_timestamp : 48;
            egress_global_timestamp : 48;
            lf_field_list : 8;
            mcast_grp : 16;
            egress_rid : 16;
            resubmit_flag : 8;
            recirculate_flag : 8;
               }
            }
metadata intrinsic_metadata_t intrinsic_metadata;


//==========addtional headers========
// hash values and counts
header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
        hash_val1: 16;
        hash_val2: 16;
        hash_val3: 16;
        hash_val4: 16;
        hash_val5: 16;
        hash_val6: 16;
        hash_val7: 16;
        hash_val8: 16;
        hash_val9: 16;
        hash_val10: 16;
        
        count_val1: 32;
        count_val2: 32;
        count_val3: 32;
        count_val4: 32;
        count_val5: 32;
        count_val6: 32;
        count_val7: 32;
        count_val8: 32;
        count_val9: 32;
        count_val10: 32;
      
        count_min: 32;
        count_tot: 32;
        sample_threshold: 32;
        index: 16;
        hh_threshold : 32; 
        count_max: 32;
        count_max_final: 32;
        sample_hash_value: 32;
        current_count: 32;
        sum: 32;
    }
}

metadata custom_metadata_t custom_metadata;
// store src, dst and counts
header_type heavy_hitter_t{
        fields {
            srcAddr: 32;
            dstAddr: 32;
            count: 32;
            }
}
metadata heavy_hitter_t heavy_hitter;

//
//



// Define the field list to compute the hash on

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation heavy_hitter_hash1 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_1;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash2 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_2;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash3 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_3;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash4 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_4;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash5 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_5;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash6 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_6;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash7 {
input { 
    hash_fields;
}
algorithm : xxhash64_7;
output_width : 16;
}

field_list_calculation heavy_hitter_hash8 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_8;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash9 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_9;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash10 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_10;
    output_width : 16;
}






field_list_calculation sampleList_hash {
    input { 
        hash_fields;
    }
    algorithm : crc32;
    output_width : 16;
}


// Define the registers to store the counts
register heavy_hitter_register1{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register2{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register3{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register4{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register5{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register6{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register7{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register8{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register9{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register10{
    width : 32;
    instance_count : CM_ROW;
}

// S_i
register packet_tot{
    width : 32;
    instance_count: 1;
}

register sampleList_src{
    width : 32;
    instance_count: SAMPLELIST_SIZE;
}
register sampleList_dst{
    width : 32;
    instance_count: SAMPLELIST_SIZE;
}

register sampleList_count{
    width : 32;
    instance_count: SAMPLELIST_SIZE;
}


register hh_r{
    width : 32;
    instance_count : 3;  //0: srcAddr, 1: dstAddr, 2: count
}
@pragma netro reglocked heavy_hitter_register1;
@pragma netro reglocked heavy_hitter_register2;
@pragma netro reglocked heavy_hitter_register3;
@pragma netro reglocked heavy_hitter_register4;
@pragma netro reglocked heavy_hitter_register5;
@pragma netro reglocked heavy_hitter_register6;
@pragma netro reglocked heavy_hitter_register7;
@pragma netro reglocked heavy_hitter_register8;
@pragma netro reglocked heavy_hitter_register9;
@pragma netro reglocked heavy_hitter_register10;
@pragma netro reglocked packet_tot;
@pragma netro reglocked hh_r;
@pragma netro reglocked sampleList_src;
@pragma netro reglocked sampleList_dst;
@pragma netro reglocked sampleList_count;
@pragma netro reglocked sampleList_index;
@pragma netro reglocked maximum_count;



// Actions to set heavy hitter filter
action set_heavy_hitter_count() {
//get the hash value
    modify_field_with_hash_based_offset(custom_metadata.hash_val1, 0,
                                        heavy_hitter_hash1, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val2, 0,
                                        heavy_hitter_hash2, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val3, 0,
                                        heavy_hitter_hash3, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val4, 0,
                                        heavy_hitter_hash4, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val5, 0,
                                        heavy_hitter_hash5, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val6, 0,
                                        heavy_hitter_hash6, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val7, 0,
                                        heavy_hitter_hash7, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val8, 0,
                                        heavy_hitter_hash8, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val9, 0,
                                        heavy_hitter_hash9, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val10, 0,
                                        heavy_hitter_hash10, CM_ROW);
   


//read the counter value from the register counter table
    register_read(custom_metadata.count_val1, heavy_hitter_register1, custom_metadata.hash_val1);
    register_read(custom_metadata.count_val2, heavy_hitter_register2, custom_metadata.hash_val2);
    register_read(custom_metadata.count_val3, heavy_hitter_register3, custom_metadata.hash_val3);
    register_read(custom_metadata.count_val4, heavy_hitter_register4, custom_metadata.hash_val4);
    register_read(custom_metadata.count_val5, heavy_hitter_register5, custom_metadata.hash_val5);
    register_read(custom_metadata.count_val6, heavy_hitter_register6, custom_metadata.hash_val6);
    register_read(custom_metadata.count_val7, heavy_hitter_register7, custom_metadata.hash_val7);
    register_read(custom_metadata.count_val8, heavy_hitter_register8, custom_metadata.hash_val8);
    register_read(custom_metadata.count_val9, heavy_hitter_register9, custom_metadata.hash_val9);
    register_read(custom_metadata.count_val10, heavy_hitter_register10, custom_metadata.hash_val10);

//update the counter value
    add_to_field(custom_metadata.count_val1, 0x01);
    add_to_field(custom_metadata.count_val2, 0x01);
    add_to_field(custom_metadata.count_val3, 0x01);
    add_to_field(custom_metadata.count_val4, 0x01);
    add_to_field(custom_metadata.count_val5, 0x01);
    add_to_field(custom_metadata.count_val6, 0x01);
    add_to_field(custom_metadata.count_val7, 0x01);
    add_to_field(custom_metadata.count_val8, 0x01);
    add_to_field(custom_metadata.count_val9, 0x01);
    add_to_field(custom_metadata.count_val10, 0x01);
   
//write back the register
    register_write(heavy_hitter_register1, custom_metadata.hash_val1, custom_metadata.count_val1);
    register_write(heavy_hitter_register2, custom_metadata.hash_val2, custom_metadata.count_val2);
    register_write(heavy_hitter_register3, custom_metadata.hash_val3, custom_metadata.count_val3);
    register_write(heavy_hitter_register4, custom_metadata.hash_val4, custom_metadata.count_val4);
    register_write(heavy_hitter_register5, custom_metadata.hash_val5, custom_metadata.count_val5);
    register_write(heavy_hitter_register6, custom_metadata.hash_val6, custom_metadata.count_val6);
    register_write(heavy_hitter_register7, custom_metadata.hash_val7, custom_metadata.count_val7);
    register_write(heavy_hitter_register8, custom_metadata.hash_val8, custom_metadata.count_val8);
    register_write(heavy_hitter_register9, custom_metadata.hash_val9, custom_metadata.count_val9);
    register_write(heavy_hitter_register10, custom_metadata.hash_val10, custom_metadata.count_val10);
  register_write(heavy_hitter_register1, custom_metadata.hash_val1, custom_metadata.count_val1);
    register_write(heavy_hitter_register2, custom_metadata.hash_val2, custom_metadata.count_val2);
    register_write(heavy_hitter_register3, custom_metadata.hash_val3, custom_metadata.count_val3);
    register_write(heavy_hitter_register4, custom_metadata.hash_val4, custom_metadata.count_val4);
    register_write(heavy_hitter_register5, custom_metadata.hash_val5, custom_metadata.count_val5);
    register_write(heavy_hitter_register6, custom_metadata.hash_val6, custom_metadata.count_val6);
    register_write(heavy_hitter_register7, custom_metadata.hash_val7, custom_metadata.count_val7);
    register_write(heavy_hitter_register8, custom_metadata.hash_val8, custom_metadata.count_val8);
    register_write(heavy_hitter_register9, custom_metadata.hash_val9, custom_metadata.count_val9);
    register_write(heavy_hitter_register10, custom_metadata.hash_val10, custom_metadata.count_val10);


}
@pragma netro no_lookup_caching set_heavy_hitter_count;

// Saves the ip we want to mirror in the ip_mirror_meta.ip
// for future use and sends a copy of the incomming packet
action do_copy_to_cpu(){
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID);
    }

action do_cpu_encap() {
    add_header(cpu_header);
    modify_field(cpu_header.flag, 0x01);
    }

action increment_tot(){
    register_read(custom_metadata.count_tot, packet_tot, 0);
    add_to_field(custom_metadata.count_tot, 0x01);
    register_write(packet_tot, 0, custom_metadata.count_tot);
}

action do_read_tot(){
    register_read(custom_metadata.sum, packet_tot, 0);
}
// Find the minimum value in CMS
action do_find_min1()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val1);
}

action do_find_min2()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val2);
}

action do_find_min3()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val3);
}

action do_find_min4()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val4);
}

action do_find_min5()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val5);
}
action do_find_min6()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val6);
}
action do_find_min7()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val7);
}

action do_find_min8()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val8);
}

action do_find_min9()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val9);
}
action do_find_min10()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val10);
}



action do_set_maximum()
{
    modify_field(heavy_hitter.srcAddr, ipv4.srcAddr);
    modify_field(heavy_hitter.dstAddr, ipv4.dstAddr);
    modify_field(heavy_hitter.count, custom_metadata.count_min);
                    
    register_write(hh_r, 0, heavy_hitter.srcAddr);
    register_write(hh_r, 1, heavy_hitter.dstAddr);
    register_write(hh_r, 2, heavy_hitter.count);

}

action do_read_packets()
{
    register_read(custom_metadata.count_tot, packet_tot, 0);
    modify_field(custom_metadata.sample_threshold, custom_metadata.count_tot
     * (W/THETA + 1/EPSILON_INVERSE)/K);
}

action do_read_hh_threshold()
{
    register_read(custom_metadata.count_tot, packet_tot, 0);
    modify_field(custom_metadata.hh_threshold,
    custom_metadata.count_tot * (W/THETA + 1/EPSILON_INVERSE));
}

action ipv4_forward(dstAddr, port) {
                modify_field(standard_metadata.egress_spec, port);
                modify_field(ethernet.srcAddr, ethernet.dstAddr);
                modify_field(ethernet.dstAddr, dstAddr);
                subtract_from_field(ipv4.ttl, 1);
                }

action do_read_max_count(){
    register_read(custom_metadata.count_max, hh_r, 2);
}

action do_read_max_count_final (){
    register_read(custom_metadata.count_max_final, hh_r, 2);
}

action do_check_sampleList(){
    modify_field_with_hash_based_offset(custom_metadata.sample_hash_value, 0,
                                        sampleList_hash, SAMPLELIST_SIZE);
    register_read(custom_metadata.current_count, sampleList_count, custom_metadata.sample_hash_value);

}


action do_add_sampleList() {
    
    register_write(sampleList_src, custom_metadata.sample_hash_value, ipv4.srcAddr);
    register_write(sampleList_dst, custom_metadata.sample_hash_value, ipv4.dstAddr);
    register_write(sampleList_count, custom_metadata.sample_hash_value, custom_metadata.count_min);
}


// Define the tables to run actions

table set_heavy_hitter_count_table {
    actions {
        set_heavy_hitter_count;
    }
    size: 1;
}

//

//
table find_min1
{
    actions
    {
        do_find_min1;
        }
}
//
table find_min2
{
    actions
    {
        do_find_min2;
    }
}
//
table find_min3
{
    actions
    {
        do_find_min3;
    }
}
//
table find_min4
{
    actions
    {
        do_find_min4;
    }
}

table find_min5
{
    actions
    {
        do_find_min5;
        }
}
//
table find_min6
{
    actions
    {
        do_find_min6;
    }
}
//
table find_min7
{
    actions
    {
        do_find_min7;
    }
}
//
table find_min8
{
    actions
    {
        do_find_min8;
    }
}
table find_min9
{
    actions
    {
        do_find_min9;
        }
}
//
table find_min10
{
    actions
    {
        do_find_min10;
    }
}


//
table redirect {
    reads { standard_metadata.instance_type : exact; }
    actions { _drop; do_cpu_encap; }
    size : 16;
                }

table copy_to_cpu {
    reads { ipv4.srcAddr : exact;}
    actions {
        do_copy_to_cpu;
        }
                                                                     size : 1024;
                                                                    }

table set_maximum{
    actions{
        do_set_maximum;
    }

}
//


//
//
table ipv4_lpm{
    reads{
        ipv4.dstAddr : lpm;
        }
    actions{
        ipv4_forward;
        _drop;
        }
    size: 1024;
    }
//
//==========================================================================================================
//Time collection
//==========================================================================================================
action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

table tot_table {
    actions{
        increment_tot;
        _drop;
    }
    size: 1024;

}
table read_tot {
    actions{
        do_read_tot;
        }

}

table read_packets{
    actions{
        do_read_packets;
        }
}

table read_hh_threshold{
    actions{
        do_read_hh_threshold;
        }
}
table check_sampleList{
    actions{
        do_check_sampleList;
    }

}

table add_sampleList{
    actions{
        do_add_sampleList;
        }
}

table read_maximum_count{
    actions{
        do_read_max_count;
    }

}
table read_maximum_count_final{
    actions{
        do_read_max_count_final;
    }

}


control ingress {

    apply(read_tot);

//At the end of time interval
    if(custom_metadata.sum >= MAXIMUM_PACKETS){
        apply(read_hh_threshold);
        apply(read_maximum_count_final);
        if (custom_metadata.count_max_final > custom_metadata.hh_threshold){
        // Send Notification
        // Flag = 1
            apply(copy_to_cpu);
        }
        //reset all registers by control plane
    }


    apply(tot_table);
    apply(ipv4_lpm);
    apply(set_heavy_hitter_count_table);
    apply(find_min1);
    if(custom_metadata.count_min > custom_metadata.count_val2){
        apply(find_min2);
    }
    if(custom_metadata.count_min > custom_metadata.count_val3){
        apply(find_min3);
    }
    if(custom_metadata.count_min > custom_metadata.count_val4){
        apply(find_min4);
    }

    if(custom_metadata.count_min > custom_metadata.count_val5){
        apply(find_min5);
    }
    if(custom_metadata.count_min > custom_metadata.count_val6){
        apply(find_min6);
    }
    if(custom_metadata.count_min > custom_metadata.count_val7){
        apply(find_min7);
    }
    if(custom_metadata.count_min > custom_metadata.count_val8){
        apply(find_min8);
    }
    if(custom_metadata.count_min > custom_metadata.count_val9){
        apply(find_min9);
    }
    if(custom_metadata.count_min > custom_metadata.count_val10){
        apply(find_min10);
    }
   
    apply(read_packets);
    if(custom_metadata.count_min > MIN and custom_metadata.count_min > (custom_metadata.sample_threshold)){
        apply(check_sampleList);
        if (custom_metadata.current_count < custom_metadata.count_min){
            apply(add_sampleList);
            apply(read_maximum_count);
            if(custom_metadata.count_min > custom_metadata.count_max){
                apply(set_maximum);            
            }
        }
    }


    }

control egress {

    // Drop the packets coming from the CPU pipelane and 
    // resend only original incoming packets
    if(standard_metadata.instance_type != 1){
            apply(send_frame);    
            }else{
            apply(redirect);
            }
}
