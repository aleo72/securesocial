/**
 * Copyright 2013-2014 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package securesocial.core.services

import akka.Done
import play.api.cache.AsyncCacheApi

import scala.concurrent._
import concurrent.duration._

/**
 * An interface for the Cache API
 */
trait CacheService {

  import scala.reflect.ClassTag

  def set[T](key: String, value: T, ttlInSeconds: Int = 0): Future[Done]

  def getAs[T](key: String)(implicit ct: ClassTag[T]): Future[Option[T]]

  def remove(key: String): Future[Done]
}

object CacheService {

  /**
   * A default implementation for the CacheService based on the Play cache.
   */
  class Default(val executionContext: ExecutionContext, cacheApi: AsyncCacheApi) extends CacheService {
    import scala.reflect.ClassTag

    override def set[T](key: String, value: T, ttlInSeconds: Int): Future[Done] =
      cacheApi.set(key, value, ttlInSeconds.seconds)

    override def getAs[T](key: String)(implicit ct: ClassTag[T]): Future[Option[T]] = cacheApi.get[T](key)

    override def remove(key: String): Future[Done] = cacheApi.remove(key)
  }
}
