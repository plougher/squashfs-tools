#ifndef MERGE_SORT_H 
#define MERGE_SORT_H

/*
 * Squashfs
 *
 * Copyright (c) 2022
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * merge_sort.h
 */

/*
 * Bottom up linked list merge sort.
 *
 * Qsort and other O(n log n) algorithms work well with arrays but not
 * linked lists.  Merge sort another O(n log n) sort algorithm on the other hand
 * is not ideal for arrays (as it needs an additonal n storage locations
 * as sorting is not done in place), but it is ideal for linked lists because
 * it doesn't require any extra storage,
 */ 

#define SORT(FUNCTION_NAME, LIST_TYPE, NAME, NEXT) \
void FUNCTION_NAME(struct LIST_TYPE **head, int count) \
{ \
	struct LIST_TYPE *cur, *l1, *l2, *next; \
	int len1, len2, stride = 1; \
 \
	if(*head == NULL || count < 2) \
		return; \
 \
	/* \
	 * We can consider our linked-list to be made up of stride length \
	 * sublists.  Eacn iteration around this loop merges adjacent \
	 * stride length sublists into larger 2*stride sublists.  We stop \
	 * when stride becomes equal to the entire list. \
	 * \
	 * Initially stride = 1 (by definition a sublist of 1 is sorted), and \
	 * these 1 element sublists are merged into 2 element sublists,  which \
	 * are then merged into 4 element sublists and so on. \
	 */ \
	do { \
		l2 = *head; /* head of current linked list */ \
		cur = NULL; /* empty output list */ \
 \
		/* \
		 * Iterate through the linked list, merging adjacent sublists. \
		 * On each interation l2 points to the next sublist pair to be \
		 * merged (if there's only one sublist left this is simply added \
		 * to the output list) \
		 */ \
		while(l2) { \
			l1 = l2; \
			for(len1 = 0; l2 && len1 < stride; len1 ++, l2 = l2->NEXT); \
			len2 = stride; \
 \
			/* \
			 * l1 points to first sublist. \
			 * l2 points to second sublist. \
			 * Merge them onto the output list \
			 */ \
			while(len1 && l2 && len2) { \
				if(strcmp(l1->NAME, l2->NAME) <= 0) { \
					next = l1; \
					l1 = l1->NEXT; \
					len1 --; \
				} else { \
					next = l2; \
					l2 = l2->NEXT; \
					len2 --; \
				} \
 \
				if(cur) { \
					cur->NEXT = next; \
					cur = next; \
				} else \
					*head = cur = next; \
			} \
			/* \
			 * One sublist is now empty, copy the other one onto the \
			 * output list \
			 */ \
			for(; len1; len1 --, l1 = l1->NEXT) { \
				if(cur) { \
					cur->NEXT = l1; \
					cur = l1; \
				} else \
					*head = cur = l1; \
			} \
			for(; l2 && len2; len2 --, l2 = l2->NEXT) { \
				if(cur) { \
					cur->NEXT = l2; \
					cur = l2; \
				} else \
					*head = cur = l2; \
			} \
		} \
		cur->NEXT = NULL; \
		stride = stride << 1; \
	} while(stride < count); \
}
#endif
