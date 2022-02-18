"""
Define the events (and event arguments) that the monitor can raise
"""

import datetime

from circuits import Event

from zpm.protobuf import zwift_messages_pb2 as zwift_message
#print(f"events.py {dir()}")




class RiderEnteredWorldEvent(Event):
    """Expects RiderEnteredWorldEventArgs as first argument"""

class RiderEnteredWorldEventArgs():
    """
    Abstraction of Payload105
    """
    def __init__(self, rider_id:int=None, first_name:str=None, last_name:str=None):
        self.rider_id = rider_id;
        self.first_name = first_name;
        self.last_name = last_name;


    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.Payload105):
        obj = cls(ps.rider_id, ps.firstName, ps.lastName)
        return obj


    def __str__(self):
        return (f'RiderEnteredWorldEventArgs(rider_id: {self.rider_id}, first_name: {self.first_name}, last_name: {self.last_name}')


class RiderTimeSyncEvent(Event):
    """Expects RiderTimeSyncEventArgs as first argument"""


class RiderTimeSyncEventArgs():
    """
    Abstraction of TimeSync
    """
    def __init__(self, rider_id:int=None, world_time:int=None):
        self.rider_id = rider_id;
        self.world_time = world_time;


    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.TimeSync):
        obj = cls(ps.rider_id, ps.world_time)
        return obj


    def __str__(self):
        return (f'RiderTimeSyncEventArgs(rider_id: {self.rider_id}, world_time: {self.world_time}')


class RiderRideOnEvent(Event):
    """Expects RiderRideOnEventArgs as first argument"""


class RiderRideOnEventArgs():
    """
    Abstraction of RideOn
    """
    def __init__(self, rider_id:int=None, to_rider_id:int=None, first_name:str=None, last_name:str=None, country_code:int=None):
        self.rider_id = rider_id;
        self.to_rider_id = to_rider_id;
        self.first_name = first_name;
        self.last_name = last_name;
        self.country_code = country_code;


    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.RideOn):
        obj = cls(ps.rider_id, ps.to_rider_id, ps.firstName, ps.lastName, ps.countryCode)
        return obj


    def __str__(self):
        return (f'RiderRideOnEventArgs(rider_id: {self.rider_id}, to_rider_id: {self.to_rider_id}, first_name: {self.first_name}, last_name: {self.last_name}'
            f', country_code: {self.country_code}'
        )

class RiderChatEvent(Event):
    """Expects RiderChatEventArgs as first argument"""


class RiderChatEventArgs():
    """
    Abstraction of Chat
    """
    def __init__(self, rider_id:int=None, to_rider_id:int=None, first_name:str=None, last_name:str=None, message:str=None, avatar:str=None, country_code:int=None):
        self.rider_id = rider_id;
        self.to_rider_id = to_rider_id;
        self.first_name = first_name;
        self.last_name = last_name;
        self.message = message;
        self.avatar = avatar;
        self.country_code = country_code;


    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.Chat):
        obj = cls(ps.rider_id, ps.to_rider_id, ps.firstName, ps.lastName, ps.message, ps.avatar, ps.countryCode)
        return obj


    def __str__(self):
        return (f'RiderChatEventArgs(rider_id: {self.rider_id}, to_rider_id: {self.to_rider_id}, first_name: {self.first_name}, last_name: {self.last_name}'
            f', message: {self.message}, avatar: {self.avatar}, country_code: {self.country_code}'
        )



class IncomingMeetupEvent(Event):
    """Expects IncomingMeetupEventArgs as first argument"""


class IncomingMeetupEventArgs():
    """
    Abstraction of Meetup
    """
    def __init__(self, name:str=None, start_time:int=None, thumbnail:str=None, duration:int=None, meetup_only_view:int=None):
        self.name = name;
        self.start_time = start_time;
        self.thumbnail = thumbnail;
        self.duration = duration;
        self.meetup_only_view = meetup_only_view;


    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.Meetup):
        obj = cls(ps.name, ps.start_time, ps.thumbnail, ps.duration, ps.meetup_only_view)
        return obj


    def __str__(self):
        return (f'IncomingMeetupEventArgs(name: {self.name}, start_time: {self.start_time}, thumbnail: {self.thumbnail}, duration: {self.duration}, meetup_only_view: {self.meetup_only_view}')


class IncomingRiderStateEvent(Event):
    """Expects RiderStateEventArgs as first argument"""


class OutgoingRiderStateEvent(Event):
    """Expects RiderStateEventArgs as first argument"""


class RiderStateEventArgs():
    """
    Abstraction of PlayerState
    """
    def __init__(self, rider_id:int=None, power:int=None, heartrate:int=None, distance:int=None, elapsed_time_secs:int=None, road_location:int=None, 
                 road_id:int=None, is_forward:bool=None, course_id:int=None, watching_rider_id:int=None, world_time:int=None, x_pos:float=None, y_pos:float=None, altitude:float=None):
        self.rider_id = rider_id;
        self.power = power;
        self.heartrate = heartrate;
        self.distance = distance;
        self.elapsed_time_secs = elapsed_time_secs
        self.elapsed_time = datetime.timedelta(seconds=elapsed_time_secs)
        self.road_location = road_location
        self.road_id = road_id
        self.is_forward = is_forward
        self.course_id = course_id
        self.watching_rider_id = watching_rider_id
        self.world_time = world_time
        self.x_pos = x_pos
        self.y_pos = y_pos
        self.altitude = altitude



    @classmethod
    def InitFromProtobuf(cls, ps:zwift_message.PlayerState):
        # credit for decoding these goes to zoffline/zwift-offline/standalone.py
        road_id = (ps.f20 & 0xFF00) >> 8;
        is_forward = (ps.f19 & 0x04) != 0;
        course_id = (ps.f19 & 0xFF0000) >> 16;

        obj = cls(ps.id, ps.power, ps.heartrate, ps.distance, ps.time, ps.roadTime, road_id, is_forward, course_id, ps.watchingRiderId, ps.worldTime, ps.x, ps.y, ps.altitude)
        return obj


    def __str__(self):
        return (
            f'RiderStateEventArgs(rider_id: {self.rider_id}, power: {self.power}, heartrate: {self.heartrate}, distance: {self.distance}'
            f', elapsed_time_secs: {self.elapsed_time_secs}, elapsed_time: {self.elapsed_time}, road_location: {self.road_location}, road_id: {self.road_id}'
            f', is_forward: {self.is_forward}, course_id: {self.course_id}, watching_rider_id: {self.watching_rider_id}, world_time: {self.world_time}'
            f', x_pos: {self.x_pos}, y_pos: {self.y_pos}, altitude: {self.altitude})'
        )


class TimeoutWaitingForPacketEvent(Event):
    """Occurs when pcap_device.next() returns empty.  No arguments."""
