/*
    Copyright (C) 2016, Jaguar Land Rover. All Rights Reserved.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this file,
    You can obtain one at http://mozilla.org/MPL/2.0/.
*/


#ifndef _RVI_LIST_H_
#define _RVI_LIST_H_

typedef struct rvi_list_entry
{
    struct rvi_list_entry* next;
    void*                  pointer;

}   rvi_list_entry;


typedef struct rvi_list
{
    rvi_list_entry* listHead;
    rvi_list_entry* listTail;

    unsigned int    count;

}   rvi_list;


int rvi_list_initialize ( rvi_list* list );

int rvi_list_insert ( rvi_list* list, void* record );

int rvi_list_remove ( rvi_list* list, void* record );

int rvi_list_remove_head ( rvi_list* list, void** record );

inline unsigned int rvi_list_get_count ( rvi_list* list )
{
    return list->count;
}


#endif // _RVI_LIST_H_
