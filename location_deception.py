# coding: utf-8
#
# CS 6204 - Network Science Project - Prof. Cho
# Demetrius Davis (2019) - dldavis@vt.edu
#

import networkx as nx
import matplotlib.pyplot as plt
from importlib.resources import path
from math import sqrt
#import numpy as np
#import numpy.random as rd
#import scipy.stats
#import random
#import warnings

#
# COMMON VULNERABILITY SCORING SYSTEM (CVSS)
#
"""
    EXPLOITABILITY (E) metrics:
    - Attack Vector (AV): HP (Adjacent), LP (Network)
    - Attack Complexity (AC): HP (High), LP (Low)
    - Privileges Required (PR): HP/LP (Low)
    - User Interface (UI): HP/LP (None)

    IMPACT (I) metrics:
    - Confidentiality (C): HP/LP (Low)
    - Integrity (I): HP/LP (Low)
    - Availability (A): HP/LP (High)
"""
def get_cvss_score(is_hp_node):
    imp_score = 6.42 * (1 - ((1 - 0.22) * (1 - 0.22) * (1 - 0.56)))
    if imp_score <= 0:
        return 0
    
    exp_score = 8.22
    if is_hp_node:
        exp_score *= 0.62 * 0.44 * 0.62 * 0.85
    else:
        exp_score *= 0.85 * 0.77 * 0.62 * 0.85

    return round(min(imp_score + exp_score, 10), 1)

def normalize_vector(val_list):
    val_sum = 0
    new_val_list = []
    
    for val in val_list: val_sum += val
    if val_sum == 0: return new_val_list

    for val in val_list: new_val_list.append(val / val_sum)
    return new_val_list
#
# GRAPH FRAMEWORK
#
class rndGeometricGraph:
    def __init__(self, isDynamic):
        self.is_dynamic_network = isDynamic
        self.lp_index = 0
        self.gw_index = 0
        self.G = []
        self.hp_indices = []
        self.sorted_indices = []

    def isDynamic(self): return self.is_dynamic_network
    def isConnected(self): return nx.is_connected(self.G)
    def getHPNodes(self): return self.hp_indices;
    def getGraph(self): return self.G;
    def getGWNode(self): return self.gw_index;
    
    def getNumHPNodes(self):
        if self.lp_index == 0: return 0;
        return self.lp_index - 1;

    def selectGWNode(self):
        for node1 in nx.nodes(self.G):
            found_hp_neighbor = False

            #print("selectGWNode(): about to set GW index: " + str(node1))
            if self.is_hp_node(node1):
                #print("selectGWNode(): --> is a HP node")
                for neighbor_node in nx.neighbors(self.G, node1):
                    if self.is_hp_node(neighbor_node):
                        found_hp_neighbor = True
                #print("selectGWNode(): HP neighbor? " + str(found_hp_neighbor))
                if not found_hp_neighbor:
                    #print("selectGWNode(): setting GW index: " + str(node1))
                    self.gw_index = node1
                    self.hp_indices.remove(node1)
                    return
    
    def buildGraph(self):
        # USE COORDINATES FROM RANDOM GEOMETRIC GRAPH MAKER
        xy_list = [(197.50403657219488, 143.80989059577777), (178.61842718618587, 13.334413733464313), (90.69611357508845, 185.56214063328446), (100.06330489139583, 4.189984283804504), (70.67330665700081, 185.68482250006932), (167.0314717953816, 143.50375280752087), (137.32099884588936, 72.30420517024909), (134.5252922614822, 114.37995616326573), (93.07449738524205, 94.89854914801859), (22.58124365317331, 47.4116606580848), (70.59934017286938, 95.14816167647975), (126.68108283703535, 160.45274866141398), (43.87371467807086, 142.22896617546382), (126.19958888417607, 165.79293482900326), (199.53709841831184, 138.01421920560472), (167.30142945616248, 118.0176978634184), (184.02737067375517, 4.46703076119086), (157.84006368997638, 87.80680448839344), (54.68262192202329, 101.08184944938476), (69.15179945363496, 146.2085631492383), (33.671284457562, 84.35407858161024), (44.461370659417824, 117.41525301125282), (32.583140270665226, 102.01618428819694), (43.37270119799162, 88.3699421955956), (196.82172898965467, 51.82462527420726), (131.80242865665775, 122.06258567268169), (166.53423757692767, 56.830828341202476), (81.73676373307124, 195.22790920642882), (6.709757275185058, 38.90938734847715), (6.388075261650683, 111.33311172195985), (70.21147741530439, 4.616526186203407), (73.60521722988832, 184.31268859871943), (189.6532184249488, 21.74922914723978), (186.06457555198674, 109.56473837100766), (27.02693717071607, 124.41013257703561), (173.8069184231353, 68.41351354481829), (194.8371804370941, 66.9589731127066), (122.49796099840795, 110.1663243996621), (123.59203465736005, 108.61897362157205), (32.722774932849255, 25.94925246755324), (185.3670803232078, 79.52004175158125), (36.15313991589788, 45.90867534486076), (105.57448324095475, 70.67849402799567), (72.28133965234262, 196.0859588999963), (109.95099948625486, 167.87355674969479), (9.892797331722235, 139.41597604964917), (106.04149723651726, 166.8925384834457), (35.216326306026005, 32.51747859867664), (64.00794107117534, 89.2331852005958), (164.16823420897788, 187.37768478134373), (191.3839922559565, 132.18069964630504), (131.35335549622022, 2.865253211170682), (104.11962095006825, 6.461020006351248), (13.725911163118475, 80.4887103083719), (176.12542926034206, 71.49848573202142), (105.88231292491706, 171.98448134172506), (12.019344309421554, 170.95682993005434), (125.32817614189014, 69.70307695440997), (151.05999320087747, 83.6800553471103), (65.78325819995399, 11.900721984288886), (15.152743425486314, 122.21442893956325), (1.9298569490701079, 105.63844093947914), (139.1678087870011, 106.32835598271299), (58.90188785627921, 109.2279874931805), (194.8922041868822, 130.73809366532416), (58.97290722944104, 134.11079072923818), (119.65154812557086, 89.85129603843929), (105.00577117960258, 38.768432330870525), (192.61056037573522, 62.88089671786425), (123.38192236726697, 55.3161625883005), (192.09303681486674, 193.8550978011511), (45.35762761422133, 170.13342498069684), (5.057472018097209, 170.19425521039932), (31.193518874699745, 139.0616809237419), (50.26001969326146, 60.93002077572067), (153.67211006620212, 178.79557739480305), (195.03604128802758, 45.63508452920282), (130.44020041212877, 138.73304962967018), (163.47946957866606, 189.34559345348939), (160.73962658980497, 49.08554563326171), (125.28431074809019, 26.333048916217816), (103.0071481687244, 121.25535627756237), (85.23269567986502, 88.96499330367985), (47.811314088719726, 17.71598696215888), (56.15843628897827, 109.73037947567401), (71.52083852104225, 150.54108122624086), (25.78735102299543, 48.20067993467598), (21.321298400796085, 184.61750660757556), (7.054128425587058, 17.34009516333508), (89.9895186936499, 194.21349570483378)]

        pos = {idx: (xy_list[idx][0], xy_list[idx][1]) for idx in range(len(xy_list))}
        
        #print(len(xy_list))
        #print(pos.values())

        # Build geometric graph
        self.G = nx.random_geometric_graph(len(pos), 35, pos=pos)
        
        # Check to ensure that the graph is sufficiently connected
        self.is_connected = nx.is_connected(self.G)
        print('Is the graph connected? ' + str(self.isConnected()))
        
        if self.isConnected():
            self.classifyNodes()
        
            #print("GW node index = " + str(self.gw_index))

            color_map = []
            for index in pos.keys():
                if (index == self.gw_index): # IoT GW
                    color_map.append('yellow')
                elif (index in self.hp_indices): #HP nodes
                    color_map.append('blue')
                else: # LP nodes
                    color_map.append('red')

            nx.draw(self.G, pos, node_size=100, node_color=color_map)
            plt.draw()
            
    def classifyNodes(self):
        # Sort nodes in decreasing degree order
        self.sorted_indices = nx.convert_node_labels_to_integers(self.G, first_label=1, ordering='decreasing degree', label_attribute=None)

        node_count = len(self.sorted_indices)
        percentage_lp_nodes = 0.2 # percentage of low-performance nodes
        self.lp_index = round(percentage_lp_nodes * node_count) + 1
        sorted_nodes = self.sorted_indices.nodes()

        # Initialize the HP indices list
        node_idx = 0
        node_val = 0
        self.hp_indices.clear()
        for node in sorted_nodes:
            if (node_idx < self.lp_index):
                node_val = node - 1
                self.hp_indices.append(node_val)
            node_idx += 1

        # Set the GW node
        self.selectGWNode()
        
    def is_hp_node(self, node_in):
        index = 0
        for node in nx.nodes(self.G):
            if node == node_in and index in self.hp_indices:
                return True
            index += 1

        return False

    def num_neighbors(self, node_in): 
        cnt = 0
        for neighbor in self.G.neighbors(node_in): cnt += 1
        return cnt
    
    def num_hp_neighbors(self, node_in):
        cnt = 0
        for neighbor_node in self.G.neighbors(node_in):
            if self.is_hp_node(neighbor_node): cnt += 1
            
        return cnt

    def get_euclidean_distance(self, node1, node2):
        pos = nx.get_node_attributes(self.G, 'pos')
        xy = pos[node1]
        x1 = xy[0]
        y1 = xy[1]
        xy = pos.get(node2)
        x2 = xy[0]
        y2 = xy[1]
        #print ("get_euclidean_distance (x1,y1) = (" + str(x1) + ", " +  str(y1) + "), (x2,y2) = (" + str(x2) + ", " +  str(y2) + ")")
        #print ("get_euclidean_distance: node1 = " + str(node1) + ", node2 = " +  str(node2) + ", dist = " + str(round(sqrt( pow((x2 - x1), 2) + pow((y2 - y1), 2) ), 4)))
    
        return round(sqrt( pow((x2 - x1), 2) + pow((y2 - y1), 2) ), 4)

#
# ATTACK GRAPH GENERATION
#
class AttackGraph:
    def __init__(self, RGG_in):
        self.RGG = RGG_in
        self.start_node = self.RGG.getGWNode()
        self.goal_nodes = self.RGG.getHPNodes()
        self.vulnerability_scores = []
        self.node_scores = []
        self.comp_nodes = []
        self.attack_history = []
        self.blocked_nodes = []
        self.attack_paths = []

        self.initializeLists()

    
    def getGoalNodes(self): return self.goal_nodes

    def isBlockedNode(self, node_in):
        if node_in in self.blocked_nodes: return True
        return False
    def getBlockedNodes(self): return self.blocked_nodes
    def setBlockedNodes(self, nodes): self.blocked_nodes = nodes
    def addBlockedNode(self, node_in): self.blocked_nodes.append(node_in)
    def getBlockedNodeIndex(self, path):
        idx = 0
        for node in path: 
            if self.isBlockedNode(node): return idx
            idx += 1
        return -1

    def isCompromisedNode(self, node_in):
        if node_in in self.comp_nodes: return True
        return False
    def addCompromisedNode(self, node_in): self.comp_nodes.append(node_in)
    def getCompromisedNodes(self): return self.comp_nodes
    def getCompromisedNodeIndex(self, path):
        idx = 0
        for node in path: 
            if self.isCompromisedNode(node): return idx
            idx += 1
        return -1

    def getRandomGraph(self): return self.RGG
    def getAttackPaths(self): return self.attack_paths
    def getVulnerabilityScores(self): return self.vulnerability_scores
    def getAttackHistory(self): return self.attack_history
    def _special_sortAttackPaths(self, list_of_dicts): return list_of_dicts['score']
    def computeMeanPathScore(self, path): 
        score = 0
        cnt = 0
        for node in path:
            score += self.getNodeScore(node)
            cnt += 1
        if cnt > 0: return round(score/cnt, 2)
        return 0

    def getNodeScore(self, node_in):
        idx = self.getNodeIndex(node_in)
        if idx == -1: print("***ERROR*** (node index was not found)")
            
        return self.node_scores[idx]
    
    def getNodeIndex(self, node_in):
        idx = 0
        for node in self.RGG.getGraph().nodes():
            if node == node_in: return idx
            idx += 1
        return -1

    def initializeLists(self):
        self.vulnerability_scores = []
        self.node_scores = []
        v_score = 0
        

        # score each node
        for node in self.getRandomGraph().getGraph():
            #print("initializeLists() node = " + str(node))
            if node in self.goal_nodes: v_score = get_cvss_score(True)
            else: v_score = get_cvss_score(False)
            self.vulnerability_scores.append(v_score)

            #print("initializeLists(vuln score) = " + str(v_score))
        self.generateAttackPathsList()
        self.calculateNodeScores()
        self.updateAttackPathsList()
        #print("initializeLists(node scores): " + str(self.node_scores))

    def generateAttackPathsList(self): # Python list of dictionaries { "score": score, "path": <path> }
        self.attack_paths.clear() # clear all paths
        cnt = 1
        for path in nx.all_simple_paths(self.RGG.getGraph(), source=self.start_node, target=self.goal_nodes, cutoff=7):
            if (len(path) > 3):
                paths_dict = {"score" : cnt, "path" : path}
                #print("cnt = " + str(cnt))
                self.attack_paths.append(paths_dict)
                cnt += 1

    def calculateNodeScores(self):
        self.node_scores.clear()
        nx_neighbors = nx.k_nearest_neighbors(self.getRandomGraph().getGraph())
        high_cpp = 0
        
        for node in self.getRandomGraph().getGraph().nodes():
            path_score_sum = 0
            
            for path_dict in self.attack_paths:
                #print("calculateCPP(" + str(node) + "): path(" + str(path_dict['path']) + ")")
                if node in path_dict['path']: path_score_sum += 1
            #print("calculateCPP(" + str(node) + "): total path score sum(" + str(path_score_sum) + "), num paths = " + str(len(self.attack_paths)))
            cpp = path_score_sum / len(self.getAttackPaths())
            if node != self.getRandomGraph().getGWNode() and  path_score_sum > high_cpp:
                high_cpp = path_score_sum
    
            hp_adjacency = 1 + (self.getRandomGraph().num_hp_neighbors(node) / self.getRandomGraph().num_neighbors(node))
            #print("Found node to calculate CPP: hp_adjacency = " + str(hp_adjacency) + ", cpp = " + str(cpp))
            
            self.node_scores.append(cpp * hp_adjacency) # return CPP(t)
            #print("calculateNodeScore: " + str(cpp * hp_adjacency))

        #print("High path count = " + str(high_cpp))

    def updateAttackPathsList(self): # Python list of dictionaries { "score": score, "path": <path> }
        for paths_dict in self.attack_paths:
            paths_dict["score"]  : self.computeMeanPathScore(paths_dict["path"])

    def checkNetworkStability(self, lp_node):
        H = self.getRandomGraph().getGraph().copy()
        H.remove_node(lp_node)
        
        return nx.is_connected(H)

# SSG PLAYER BASE CLASS
class SSGplayer():
    def __init__(self, budget):
        self.coverage_probability = budget
    
    def get_ids_cost(self):
        ids_cost = 5
        return ids_cost
    
    def get_decoy_cost(self, num_nodes):
        decoy_base_cost = 3
        node_edge_decoy_cost = 0.3

        return decoy_base_cost + node_edge_decoy_cost*num_nodes
    
    def get_hide_cost(self, num_nodes):
        hide_base_cost = 2
        node_edge_hide_cost = 0.3
    
        return hide_base_cost + (node_edge_hide_cost*num_nodes)
    
    def get_location_deception_cost(self):
        ip_randomization_cost = 1
        return ip_randomization_cost

    def buildTargetNodeSet(self, attack_graph):
        node_set = []
        
        # Build target node set
        for comp_node in attack_graph.getCompromisedNodes():
            for neighbor in attack_graph.getRandomGraph().getGraph().neighbors(comp_node):
                if neighbor != attack_graph.getRandomGraph().getGWNode() and neighbor not in attack_graph.getCompromisedNodes() and neighbor not in node_set:
                    node_set.append(neighbor)

        for neighbor in attack_graph.getRandomGraph().getGraph().neighbors(attack_graph.getRandomGraph().getGWNode()):
            if neighbor not in attack_graph.getCompromisedNodes() and neighbor not in node_set:
                node_set.append(neighbor)

        return node_set
            
# NON-DECEPTION DEFENDER CLASS - inherits from SSGplayer
class GenericDefender(SSGplayer):
    def __init__(self, budget):
        self.coverage_probability = budget
        self.node_set = []
        self.pure_strategy = True

    def getDefenseCost(self):
        cost = self.get_ids_cost()
        return cost

    def selectStrategy(self, attack_graph, attack_strategy):
        # Iterate through each available node to find best defensive strategy
        u_d = []
        self.node_set = self.buildTargetNodeSet(attack_graph)
        node_score_total = 0
        c_t = self.coverage_probability
        
        print("forwarded Attack strategy: " + str(attack_strategy))
        
        # Calculate sum of node scores in node_set
        for node in self.node_set:
            node_score_total += attack_graph.getNodeScore(node)
        
        idx = 0
        for node in attack_graph.getRandomGraph().getGraph().nodes():

            if len(attack_strategy) == 0: # pure strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost()
                    p_n = self.coverage_probability * len(self.node_set) + (attack_graph.getNodeScore(node) - self.getDefenseCost())
                    p_n = c_t * u_d_covered + (1 - c_t) * u_d_uncovered
                    print("Def. Pure Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
            
            else: # mixed strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost()
                    #p_n = self.coverage_probability * len(self.node_set)
                    p_n = attack_strategy[idx] * u_d_covered + (1 - attack_strategy[idx]) * u_d_uncovered
                    print("Def. Mixed Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
                
            idx += 1
            
        print("U_d(): { " + str(normalize_vector(u_d)) + " }")
        return normalize_vector(u_d)
    
        '''
        # Cap the number of defensive resources to allow one pure strategy move by the attacker
        for path_dict in attack_graph.getAttackPaths():
            path_score = path_dict["score"]
            path = path_dict["path"]
            count += 1
            if (count > self.budget): break
            
            high_score = 0
            low_key = 0
            for path_key in paths_dict:
                if path_key in selected_paths: continue

                score = attack_graph.computeMeanPathScore(paths_dict[path_key])
                if score > high_score:
                    high_score = score
                    high_score_key = path_key
                    high_score_path = paths_dict[path_key]

            if high_score > 0:
                flag = True

                comp_node_idx = attack_graph.getCompromisedNodeIndex(high_score_path)
                if comp_node_idx < 0: # no compromised nodes on the path
                    for node in high_score_path:
                        if flag: flag = False
                        elif (node not in attack_graph.getCompNodes()) and (node not in covered_nodes):
                            covered_nodes.append(node) # cover the priority LP node
                            selected_paths.append(high_score_key)
                            print("Covering node[" + str(node) + "], key-path[" + str(high_score_key) + "]: " + str(high_score_path))
                            break
                else:
                    for node_idx in range(comp_node_idx,len(high_score_path)):
                        if (high_score_path[node_idx] not in attack_graph.getCompNodes()) and (high_score_path[node_idx] not in covered_nodes):
                            covered_nodes.append(high_score_path[node_idx]) # cover the priority LP node
                            selected_paths.append(high_score_key)
                            print("Covering node[" + str(high_score_path[node_idx]) + "], key-path[" + str(high_score_key) + "]: " + str(high_score_path))
                            break

        c_t = []
        attack_graph.setBlockedNodes(covered_nodes)

        for idx in range(len(attack_graph.getRandomGraph().getGraph().nodes)):
            if idx in covered_nodes:
                c_t.append(True)
            else:
                c_t.append(False)

        #print("Defense strategy: ")
        #print(c_t)
        
        return c_t # return C* as a response to the defender's move
        '''
   
# DECEPTION DEFENDER CLASS - inherits from SSGplayer
class DeceptionDefender(SSGplayer):
    def __init__(self, budget):
        self.coverage_probability = budget
        self.node_set = []
        self.fake_node_set = []
        self.hidden_nodes = []
        self.pure_strategy = True

    def getDefenseCost(self, num_nodes):
        cost = self.get_hide_cost(num_nodes)
        return cost

    def selectStrategy(self, attack_graph, attack_strategy):
        # Iterate through each available node to find best defensive strategy
        u_d = []
        self.node_set = self.buildTargetNodeSet(attack_graph)
        node_score_total = 0
        budget = round(self.coverage_probability * len(self.node_set))
        c_t = self.coverage_probability
        
        print("forwarded Attack strategy: " + str(attack_strategy))
        
        # Calculate sum of node scores in node_set
        for node in self.node_set:
            node_score_total += attack_graph.getNodeScore(node)
        
        idx = 0
        for node in attack_graph.getRandomGraph().getGraph().nodes():

            if len(attack_strategy) == 0: # pure strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost(budget)
                    p_n = self.coverage_probability * len(self.node_set) + (attack_graph.getNodeScore(node) - self.getDefenseCost(budget))
                    p_n = c_t * u_d_covered + (1 - c_t) * u_d_uncovered
                    print("Def. Pure Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
            
            else: # mixed strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost(budget)
                    #p_n = self.coverage_probability * len(self.node_set)
                    p_n = attack_strategy[idx] * u_d_covered + (1 - attack_strategy[idx]) * u_d_uncovered
                    print("Def. Mixed Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
                
            idx += 1

        # Hide high-scoring nodes from node set
        self.fake_node_set = self.node_set.copy()
        
        for cnt in range(budget):
            high_score = 0
            node_idx = 0
            flag = False
            
            for score in u_d:
                #print("Iterating thru def_strategy[" + str(node_idx) + "] = " + str(score))
                if score > high_score and node_idx not in attack_graph.getCompromisedNodes() and  node_idx not in self.hidden_nodes:
                    high_score = score
                    high_score_node = node_idx
                    flag = True
                node_idx += 1
                    
            if flag:
                print("...hiding a node: " + str(high_score_node))
                self.hidden_nodes.append(high_score_node)
                self.fake_node_set.remove(high_score_node)
            
        print("(Real) node set: { " + str(self.node_set) + " }, (Fake) node set: {" + str(self.fake_node_set) + " }")
        print("U_d(): { " + str(normalize_vector(u_d)) + " }")
        return normalize_vector(u_d)

# LOCATION DECEPTION DEFENDER CLASS - inherits from SSGplayer
class LocDecDefender(SSGplayer):
    def __init__(self, budget):
        self.coverage_probability = budget
        self.pure_strategy = True
        self.decoy_nodes = []

    def getDefenseCost(self, num_nodes):
        cost = self.get_decoy_cost(num_nodes) + self.get_location_deception_cost()
        return cost
    
    def selectStrategy(self, attack_graph, attack_strategy):
        # Iterate through each available node to find best defensive strategy
        u_d = []
        self.node_set = self.buildTargetNodeSet(attack_graph)
        node_score_total = 0
        budget = round(self.coverage_probability * len(self.node_set))
        c_t = self.coverage_probability
        self.decoy_nodes.clear()
        
        print("forwarded Attack strategy: " + str(attack_strategy))
        
        # Calculate sum of node scores in node_set
        for node in self.node_set:
            node_score_total += attack_graph.getNodeScore(node)
        
        idx = 0
        for node in attack_graph.getRandomGraph().getGraph().nodes():

            if len(attack_strategy) == 0: # pure strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost(budget)
                    p_n = self.coverage_probability * len(self.node_set) + (attack_graph.getNodeScore(node) - self.getDefenseCost(budget))
                    p_n = c_t * u_d_covered + (1 - c_t) * u_d_uncovered
                    print("Def. Pure Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
            
            else: # mixed strategy
                if node in self.node_set:
                    u_d_covered = attack_graph.getNodeScore(node)
                    u_d_uncovered = self.getDefenseCost(budget)
                    #p_n = self.coverage_probability * len(self.node_set)
                    p_n = attack_strategy[idx] * u_d_covered + (1 - attack_strategy[idx]) * u_d_uncovered
                    print("Def. Mixed Strategy(" + str(node) + "): p_n = " + str(p_n))
                    u_d.append(p_n)

                else: u_d.append(0)
                
            idx += 1

        for cnt in range(budget):
            high_score = 0
            node_idx = 0
            flag = False
            
            for score in u_d:
                #print("Iterating thru def_strategy[" + str(node_idx) + "] = " + str(score))
                if score > high_score and node_idx not in attack_graph.getCompromisedNodes() and  node_idx not in self.decoy_nodes:
                    high_score = score
                    high_score_node = node_idx
                    flag = True
                node_idx += 1
                    
            if flag:
                print("...protecting a node with decoys: " + str(high_score_node))
                self.decoy_nodes.append(high_score_node)
            
        return normalize_vector(u_d)

# GENERIC ATTACKER CLASS - inherits from SSGplayer
class GenericAttacker(SSGplayer):
    def __init__(self, budget):
        self.budget = budget

    def getAttackCost(self):
        cost = 1 # attack cost
        return cost

    def calculateAverageDistance(self, attack_graph, start):
        total_dist = 0
        
        # Add GW to comp nodes
        for goal in attack_graph.goal_nodes:
            total_dist += attack_graph.getRandomGraph().get_euclidean_distance(start, goal)

        #print("avg dist(" + str(start) + "): total_dist = " + str(total_dist) + ", num goals = " + str(len(attack_graph.goal_nodes)) + ", avg dist = " + str(total_dist / len(attack_graph.goal_nodes)))
        return total_dist / len(attack_graph.goal_nodes) # in meters
        
    def selectStrategy(self, attack_graph, node_set, def_strategy):
        u_a = []
        idx = 0
        for c_t in def_strategy:
            if idx in node_set:
                u_covered = 0 - self.getAttackCost()
                #print("attacker.selectStrategy(" + str(idx) + ") avg dist = " + str(self.calculateAverageDistance(attack_graph, idx)))
                u_not_covered = self.calculateAverageDistance(attack_graph, idx) - self.getAttackCost()
                u_a.append(c_t * u_covered + (1 - c_t) * u_not_covered)
            else: u_a.append(0)
            idx += 1
            
        print("U_a(): { " + str(normalize_vector(u_a)) + " }")
        return normalize_vector(u_a)

#
# SSG FRAMEWORK
#
class SSGDeceptionModeler:
    """
    StackelbergSecurityGame (SSG) is a bayesian normal-form stackelberg game and holds the
    following values:
    -- defender: network defender
    -- attacker: attacker/adversary
    -- c_x[l]: defender's payoff for delaying adversary
    
    -- Three  defense strategies are applied: non-deception, deception and location deception
    """
    
    def __init__(self, attack_graph_in, is_dynamic_network, dec_method_in, budget):
        self.att_budget = 1
        self.coverage_probability = budget
        self.uncertainty = 0
        self.attack_graph = attack_graph_in
        self.deception_method = dec_method_in
        self.blocked_attacks = []
        self.hidden_nodes = []
        self.decoy_nodes = []
        self.attack_history = []
        self.comp_nodes = []
        self.def_strategy = []
        self.att_strategy = []
        
        print("Defense budget = " + str(self.coverage_probability) + ", Deg of GW node = " + str(self.attack_graph.getRandomGraph().num_neighbors(self.attack_graph.getRandomGraph().getGWNode())))

        # Three defender types and one attacker
        self.ssg_defender = GenericDefender(self.coverage_probability)
        self.dec_defender = DeceptionDefender(self.coverage_probability)
        self.loc_dec_defender = LocDecDefender(self.coverage_probability)
        self.attacker = GenericAttacker(self.att_budget)
    
    def playStaticGame(self):
        node_set = []

        if self.deception_method == 1:
            #1: Non-deception defender move -- cover or no-cover
            self.def_strategy = self.ssg_defender.selectStrategy(self.attack_graph, self.att_strategy)
            node_set = self.ssg_defender.node_set

        elif self.deception_method == 2:
            #2: Deception defender move -- mask location, hide nodes/edges, create decoy nodes/edges
            self.def_strategy = self.dec_defender.selectStrategy(self.attack_graph, self.att_strategy)
            node_set = self.dec_defender.node_set
            self.hidden_nodes = self.dec_defender.hidden_nodes

        elif self.deception_method == 3:
            #3: Location deception defender move -- mask location, hide nodes/edges, create decoy nodes/edges
            self.def_strategy = self.loc_dec_defender.selectStrategy(self.attack_graph, self.att_strategy)
            node_set = self.loc_dec_defender.node_set
            self.decoy_nodes = self.loc_dec_defender.decoy_nodes

        self.att_strategy = self.attacker.selectStrategy(self.attack_graph, node_set, self.def_strategy)
        self.computePayoffs(node_set)

        return 0
        
    def computePayoffs(self, node_set):
        budget = round(self.coverage_probability * len(node_set))

        if self.deception_method == 1:
            uncovered_attack = False
            
            self.attack_graph.blocked_nodes.clear() # empty blocked nodes
            
            # Block m nodes
            while len(self.attack_graph.getBlockedNodes()) < budget:
                #print("inside computePayoffs() num blocked nodes = " + str(self.attack_graph.getBlockedNodes()) + ", budget = " + str(budget))
                high_score = 0
                high_score_node = 0
                score = 0
                node_idx = 0
                flag = False
                
                for score in self.def_strategy:
                    #print("Iterating thru def_strategy[" + str(node_idx) + "] = " + str(score))
                    if score > high_score and node_idx not in self.attack_graph.getBlockedNodes() and node_idx not in self.attack_graph.getCompromisedNodes():
                        high_score = score
                        high_score_node = node_idx
                        flag = True
                    node_idx += 1
                        
                if flag:
                    self.attack_graph.addBlockedNode(high_score_node)
                    #print("added a blocked node: " + str(high_score_node))
                
            print("Blocked nodes(budget=" + str(budget) + "): " + str(self.attack_graph.getBlockedNodes()) + ", comp nodes = " + str(self.attack_graph.getCompromisedNodes()))
        
        elif self.deception_method == 2:
            self.hidden_nodes.clear() # empty blocked nodes
            
            # Block m nodes
            while len(self.hidden_nodes) < budget:
                #print("inside computePayoffs() num blocked nodes = " + str(self.attack_graph.getBlockedNodes()) + ", budget = " + str(budget))
                high_score = 0
                high_score_node = 0
                score = 0
                node_idx = 0
                flag = False
                
                for score in self.def_strategy:
                    #print("Iterating thru def_strategy[" + str(node_idx) + "] = " + str(score))
                    if score > high_score and node_idx not in self.hidden_nodes and node_idx not in self.attack_graph.getCompromisedNodes():
                        high_score = score
                        high_score_node = node_idx
                        flag = True
                    node_idx += 1
                        
                if flag:
                    self.hidden_nodes.append(high_score_node)
                    print("added a hidden node: " + str(high_score_node))
                
            print("Hidden nodes (budget=" + str(budget) + "): " + str(self.hidden_nodes) + ", comp nodes = " + str(self.attack_graph.getCompromisedNodes()))

        elif self.deception_method == 3:
            self.decoy_nodes.clear() # empty blocked nodes
            
            # Block m nodes
            while len(self.decoy_nodes) < budget:
                #print("inside computePayoffs() num blocked nodes = " + str(self.attack_graph.getBlockedNodes()) + ", budget = " + str(budget))
                high_score = 0
                high_score_node = 0
                score = 0
                node_idx = 0
                flag = False
                
                for score in self.def_strategy:
                    #print("Iterating thru def_strategy[" + str(node_idx) + "] = " + str(score))
                    if score > high_score and node_idx not in self.decoy_nodes and node_idx not in self.attack_graph.getCompromisedNodes():
                        high_score = score
                        high_score_node = node_idx
                        flag = True
                    node_idx += 1
                        
                if flag:
                    self.decoy_nodes.append(high_score_node)
                    print("added a decoy node: " + str(high_score_node))
                
            print("Decoy nodes (budget=" + str(budget) + "): " + str(self.decoy_nodes) + ", comp nodes = " + str(self.attack_graph.getCompromisedNodes()))
            
        high_score = 0
        node_idx = 0
        attack_node = -1
        
        # identify attacked node
        for score in self.att_strategy:
            if score > high_score and node_idx not in self.attack_graph.getCompromisedNodes():
                high_score = score
                attack_node = node_idx
            node_idx += 1

        if attack_node in self.attack_graph.getBlockedNodes():
            self.attack_history.append(attack_node)
            print("...BLOCKED ATTACK!... [" + str(attack_node) + "]")
            self.blocked_attacks.append(attack_node)
            
        elif attack_node in self.hidden_nodes:
            self.attack_history.append(attack_node)
            print("...WHIFFED (hidden) ATTACK!... [" + str(attack_node) + "]")
            self.uncertainty += 1
            
        elif attack_node in self.decoy_nodes:
            self.attack_history.append(attack_node)
            print("...WHIFFED (decoy) ATTACK!... [" + str(attack_node) + "]")
            self.uncertainty += 1
            
        elif attack_node >= 0:
            self.attack_history.append(attack_node)
            print("...UNCOVERED ATTACK!... [" + str(attack_node) + "]")
            self.attack_graph.addCompromisedNode(attack_node)

    def isGameOver(self):
        for comp_node in self.attack_graph.getCompromisedNodes():
            if comp_node in self.attack_graph.getGoalNodes():
                print("****isGameOver(): compromised HP node = " + str(comp_node))
                return True

        return False

    def getAttackGraph(self): return self.attack_graph
    def getUncertainty(self): return self.uncertainty
    def getCompromisedNodeCount(self): return len(self.attack_graph.getCompromisedNodes())

#
# SECTION 1 - BUILD NETWORK / BUILD ATTACK GRAPH / INITIATE SSG PLAY
#
is_dynamic_network = False
deception_method = 3 # 1 - no deception, 2 - deception (hide edges), 3 - location deception (decoy nodes)
coverage_probability = .75
def_strategy = []
att_strategy = []

# Build random geometric graph
G = rndGeometricGraph(is_dynamic_network)
G.buildGraph()

# Build attack graph
attackGraph = AttackGraph(G)

ssg = SSGDeceptionModeler(attackGraph, is_dynamic_network, deception_method, coverage_probability)

# Game result: 1 - not all results in yet (keep playing); 0 - Defender wins
game_count = 0
while (not ssg.isGameOver()) and (game_count < 25):
    ssg.playStaticGame()
    print("Completed a static SSG.")
    game_count += 1
    
print ("---> Equilibrium achieved. DONE.")

print("UNCERTAINTY = " + str(ssg.getUncertainty()))
print("# of ATTACKS = " + str(len(ssg.attack_history)) + ", ATTACK HISTORY = " + str(ssg.attack_history))
print("# of BLOCKED ATTACKS = " + str(len(ssg.blocked_attacks)))
print("GAME COUNT = " + str(game_count))
print("# of HIDDEN NODES = " + str(len(ssg.hidden_nodes)))
print("# of BLOCKED NODES = " + str(len(ssg.getAttackGraph().getBlockedNodes())))
print("# of DECOY NODES = " + str(len(ssg.decoy_nodes)))
print("# of COMP NODES = " + str(ssg.getCompromisedNodeCount()))
print("ASP = " + str(ssg.getCompromisedNodeCount() / game_count))
